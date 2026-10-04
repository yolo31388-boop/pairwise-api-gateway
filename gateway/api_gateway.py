"""
游戏内API网关与限流熔断系统 - 核心模块

修复内容：
- 路由：支持路径参数（/api/players/{player_id}）与优先级（静态段优先，可用 priority 覆盖）
- 限流：按用户独立计数，超限惩罚（封禁，重复违规封禁时间加倍）
- 熔断：按服务统计错误率，达到阈值熔断，冷却后进半开状态试探恢复
- 降级：注册默认响应，服务不可用时返回降级结果并产生玩家可见通知
- 认证：token 签发/校验/过期，按角色分级控制接口权限
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
import time
import uuid


# 角色权限等级：数值越大权限越高
ROLE_LEVELS = {
    "guest": 0,
    "player": 1,
    "vip": 2,
    "admin": 3,
}

# 各角色默认限流配额（次/窗口）
DEFAULT_ROLE_LIMITS = {
    "guest": 10,
    "player": 60,
    "vip": 120,
    "admin": 1000,
}


@dataclass
class Config:
    """网关配置（均可用 dict 覆盖）"""
    rate_limit: int = 60                 # 默认限流配额（次/窗口）
    rate_window: float = 60.0            # 限流窗口（秒）
    ban_duration: float = 300.0          # 超限封禁时长（秒），重复违规加倍
    circuit_error_threshold: float = 0.5   # 熔断错误率阈值
    circuit_min_requests: int = 5          # 触发熔断所需的最少样本数
    circuit_cooldown: float = 30.0       # 熔断冷却时长（秒），之后进入半开
    circuit_half_open_probes: int = 3    # 半开状态允许的试探请求数
    token_ttl: float = 3600.0            # token 有效期（秒）


@dataclass
class Route:
    method: str
    pattern: str
    service: str
    min_role: str = "guest"
    priority: int = 0
    segments: Tuple[str, ...] = ()

    def specificity(self) -> Tuple[int, int, int]:
        """路由优先级：显式 priority > 静态段数量 > 路径长度"""
        static_count = sum(1 for s in self.segments if not self._is_param(s))
        return (self.priority, static_count, len(self.pattern))

    @staticmethod
    def _is_param(segment: str) -> bool:
        return (segment.startswith("{") and segment.endswith("}")) or segment.startswith(":")


@dataclass
class RouteMatch:
    route: Route
    params: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuthContext:
    user_id: str
    role: str
    expires_at: float


class APIGateway:
    def __init__(self, config: Optional[Any] = None):
        if isinstance(config, Config):
            self.config = config
        else:
            self.config = Config(**(config or {}))

        # 虚拟时钟（秒），update(dt) 推进，便于确定性测试
        self._now = 0.0

        # 路由表
        self._routes: List[Route] = []

        # 限流状态：user_id -> {"count": int, "window_start": float,
        #                     "banned_until": float, "violations": int}
        self._rate_state: Dict[str, Dict[str, Any]] = {}
        # 显式配置了 rate_limit 时，所有角色默认都用该配额
        if isinstance(config, dict) and "rate_limit" in config:
            self._role_limits = {role: self.config.rate_limit for role in ROLE_LEVELS}
        else:
            self._role_limits = dict(DEFAULT_ROLE_LIMITS)

        # 熔断器状态：service -> {...}
        self._circuits: Dict[str, Dict[str, Any]] = {}

        # 降级：service -> {"default": Any, "handler": Callable|None}
        self._fallbacks: Dict[str, Dict[str, Any]] = {}
        self._notifications: List[Dict[str, Any]] = []

        # 认证：token -> AuthContext
        self._tokens: Dict[str, AuthContext] = {}

        # 后端服务处理器：service -> Callable
        self._services: Dict[str, Callable] = {}

        self._state: Dict[str, Any] = {}
        self._history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 时钟
    # ------------------------------------------------------------------
    def update(self, dt: float):
        """推进内部时钟并执行周期任务（半开试探重置等）"""
        self._now += float(dt)
        for state in self._circuits.values():
            if (state["state"] == "open"
                    and self._now - state["opened_at"] >= self.config.circuit_cooldown):
                state["state"] = "half_open"
                state["half_open_probes"] = 0

    def reset(self):
        self._now = 0.0
        self._routes = []
        self._rate_state = {}
        self._circuits = {}
        self._fallbacks = {}
        self._notifications = []
        self._tokens = {}
        self._services = {}
        self._state = {}
        self._history = []

    # ------------------------------------------------------------------
    # 路由：路径参数 + 优先级
    # ------------------------------------------------------------------
    def add_route(self, pattern: str, service: str, method: str = "ANY",
                  min_role: str = "guest", priority: int = 0) -> Route:
        if min_role not in ROLE_LEVELS:
            raise ValueError(f"未知角色: {min_role}")
        segments = tuple(s for s in pattern.strip("/").split("/") if s)
        route = Route(method=method.upper(), pattern=pattern, service=service,
                      min_role=min_role, priority=priority, segments=segments)
        self._routes.append(route)
        return route

    def _match_route(self, route: Route, path: str) -> Optional[Dict[str, str]]:
        parts = [s for s in path.strip("/").split("/") if s]
        if len(parts) != len(route.segments):
            return None
        params: Dict[str, str] = {}
        for seg, part in zip(route.segments, parts):
            if Route._is_param(seg):
                name = seg.strip("{}") if seg.startswith("{") else seg[1:]
                params[name] = part
            elif seg != part:
                return None
        return params

    def route_request(self, path: str, method: str = "GET") -> Optional[RouteMatch]:
        """按优先级匹配路由，返回命中的路由与路径参数"""
        method = method.upper()
        candidates: List[Tuple[Tuple[int, int, int], Route, Dict[str, str]]] = []
        for route in self._routes:
            if route.method not in ("ANY", method):
                continue
            params = self._match_route(route, path)
            if params is not None:
                candidates.append((route.specificity(), route, params))
        if not candidates:
            return None
        # 优先级高者优先；静态段多的特定路由优先于通用路由
        candidates.sort(key=lambda item: item[0], reverse=True)
        _, route, params = candidates[0]
        return RouteMatch(route=route, params=params)

    # ------------------------------------------------------------------
    # 限流：按用户计数 + 超限封禁惩罚
    # ------------------------------------------------------------------
    def set_role_limit(self, role: str, limit: int):
        if role not in ROLE_LEVELS:
            raise ValueError(f"未知角色: {role}")
        self._role_limits[role] = int(limit)

    def _user_state(self, user_id: str) -> Dict[str, Any]:
        state = self._rate_state.get(user_id)
        if state is None:
            state = {"count": 0, "window_start": self._now,
                     "banned_until": 0.0, "violations": 0}
            self._rate_state[user_id] = state
        return state

    def rate_limit(self, user_id: str, role: str = "player") -> bool:
        """返回 True 表示放行；超限会被封禁一段时间（重复违规加倍）"""
        state = self._user_state(user_id)

        # 封禁期内直接拒绝
        if self._now < state["banned_until"]:
            return False

        # 窗口滚动
        if self._now - state["window_start"] >= self.config.rate_window:
            state["count"] = 0
            state["window_start"] = self._now

        limit = self._role_limits.get(role, self.config.rate_limit)
        if state["count"] >= limit:
            # 超限惩罚：封禁，重复违规封禁时长加倍
            state["violations"] += 1
            state["banned_until"] = self._now + self.config.ban_duration * state["violations"]
            state["count"] = 0
            state["window_start"] = self._now
            return False

        state["count"] += 1
        return True

    def is_banned(self, user_id: str) -> bool:
        state = self._rate_state.get(user_id)
        return bool(state) and self._now < state["banned_until"]

    # ------------------------------------------------------------------
    # 熔断器：错误率阈值 + 半开恢复
    # ------------------------------------------------------------------
    def _circuit(self, service: str) -> Dict[str, Any]:
        circuit = self._circuits.get(service)
        if circuit is None:
            circuit = {"state": "closed", "successes": 0, "failures": 0,
                       "opened_at": 0.0, "half_open_probes": 0}
            self._circuits[service] = circuit
        return circuit

    def _refresh_circuit(self, circuit: Dict[str, Any]):
        if (circuit["state"] == "open"
                and self._now - circuit["opened_at"] >= self.config.circuit_cooldown):
            circuit["state"] = "half_open"
            circuit["half_open_probes"] = 0

    def circuit_breaker(self, service: str) -> bool:
        """返回 True 表示允许向该服务转发请求"""
        circuit = self._circuit(service)
        self._refresh_circuit(circuit)
        if circuit["state"] == "closed":
            return True
        if circuit["state"] == "open":
            return False
        # half_open：只允许少量试探请求
        if circuit["half_open_probes"] < self.config.circuit_half_open_probes:
            circuit["half_open_probes"] += 1
            return True
        return False

    def record_result(self, service: str, success: bool):
        """记录一次后端调用结果，驱动熔断/恢复"""
        circuit = self._circuit(service)
        if success:
            circuit["successes"] += 1
            if circuit["state"] == "half_open":
                # 试探成功：关闭熔断器，恢复转发
                circuit["state"] = "closed"
                circuit["successes"] = 0
                circuit["failures"] = 0
                circuit["half_open_probes"] = 0
        else:
            circuit["failures"] += 1
            if circuit["state"] == "half_open":
                # 试探失败：重新熔断
                circuit["state"] = "open"
                circuit["opened_at"] = self._now
                circuit["half_open_probes"] = 0
                return
            total = circuit["successes"] + circuit["failures"]
            if (circuit["state"] == "closed"
                    and total >= self.config.circuit_min_requests
                    and circuit["failures"] / total >= self.config.circuit_error_threshold):
                circuit["state"] = "open"
                circuit["opened_at"] = self._now

    def circuit_state(self, service: str) -> str:
        circuit = self._circuit(service)
        self._refresh_circuit(circuit)
        return circuit["state"]

    # ------------------------------------------------------------------
    # 降级：默认响应 + 玩家通知
    # ------------------------------------------------------------------
    def register_fallback(self, service: str, default: Any = None,
                          handler: Optional[Callable] = None):
        self._fallbacks[service] = {"default": default, "handler": handler}

    def fallback(self, service: str, request: Optional[Dict] = None) -> Dict[str, Any]:
        """服务不可用时返回降级响应，并记录一条玩家可见的通知"""
        entry = self._fallbacks.get(service, {"default": None, "handler": None})
        if entry["handler"] is not None:
            data = entry["handler"](request)
        else:
            data = entry["default"]
        if data is None:
            data = {"message": f"服务 {service} 暂不可用，请稍后再试"}
        notification = {
            "type": "degraded",
            "service": service,
            "message": f"服务 {service} 已降级，部分功能可能不可用",
            "time": self._now,
        }
        self._notifications.append(notification)
        return {"status": 200, "degraded": True, "service": service,
                "data": data, "notification": notification}

    def get_notifications(self) -> List[Dict[str, Any]]:
        return list(self._notifications)

    # ------------------------------------------------------------------
    # 认证：token 过期 + 角色权限分级
    # ------------------------------------------------------------------
    def issue_token(self, user_id: str, role: str = "player",
                    ttl: Optional[float] = None) -> str:
        if role not in ROLE_LEVELS:
            raise ValueError(f"未知角色: {role}")
        token = uuid.uuid4().hex
        expires = self._now + (ttl if ttl is not None else self.config.token_ttl)
        self._tokens[token] = AuthContext(user_id=user_id, role=role, expires_at=expires)
        return token

    def authenticate(self, token: Optional[str]) -> Optional[AuthContext]:
        """校验 token，过期自动失效"""
        if not token:
            return None
        ctx = self._tokens.get(token)
        if ctx is None:
            return None
        if self._now >= ctx.expires_at:
            del self._tokens[token]
            return None
        return ctx

    def auth_middleware(self, token: Optional[str],
                        required_role: str = "guest") -> Tuple[bool, Optional[AuthContext], Optional[str]]:
        """认证 + 权限分级校验，返回 (是否通过, 上下文, 错误码)"""
        ctx = self.authenticate(token)
        if ctx is None:
            return False, None, "invalid_token"
        if ROLE_LEVELS[ctx.role] < ROLE_LEVELS[required_role]:
            return False, ctx, "forbidden"
        return True, ctx, None

    # ------------------------------------------------------------------
    # 端到端请求处理：认证 -> 路由 -> 限流 -> 熔断 -> 转发/降级
    # ------------------------------------------------------------------
    def register_service(self, service: str, handler: Callable[[Dict], Any]):
        self._services[service] = handler

    def handle_request(self, path: str, method: str = "GET",
                       token: Optional[str] = None,
                       body: Optional[Dict] = None) -> Dict[str, Any]:
        match = self.route_request(path, method)
        if match is None:
            return {"status": 404, "error": "not_found"}

        route = match.route
        ok, ctx, err = self.auth_middleware(token, route.min_role)
        if not ok:
            return {"status": 401 if err == "invalid_token" else 403, "error": err}

        user_id = ctx.user_id if ctx else "anonymous"
        role = ctx.role if ctx else "guest"
        if not self.rate_limit(user_id, role):
            return {"status": 429, "error": "rate_limited", "banned": self.is_banned(user_id)}

        service = route.service
        request = {"path": path, "method": method, "params": match.params,
                   "body": body or {}, "user_id": user_id}

        if not self.circuit_breaker(service):
            return self.fallback(service, request)

        handler = self._services.get(service)
        if handler is None:
            self.record_result(service, False)
            return self.fallback(service, request)
        try:
            data = handler(request)
            self.record_result(service, True)
            return {"status": 200, "degraded": False, "service": service, "data": data}
        except Exception as exc:  # 后端异常：记录失败并降级
            self.record_result(service, False)
            result = self.fallback(service, request)
            result["upstream_error"] = str(exc)
            return result
