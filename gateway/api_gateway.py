"""
游戏内API网关与限流熔断系统 - 核心模块

功能：
- 路由：支持路径参数（/api/players/{player_id}）与优先级（特定路由优先于通用路由）
- 限流：按用户独立限流（令牌桶），超限惩罚（违规次数达到阈值后封禁一段时间）
- 熔断：失败阈值触发熔断，冷却后进半开状态，试探成功则恢复
- 降级：服务不可用时返回默认响应，并携带降级通知
- 认证：token 校验、角色权限分级、token 过期
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import math
import re
import time
import uuid


@dataclass
class Config:
    pass


# 角色权限等级，数值越大权限越高
ROLE_LEVELS = {
    "player": 1,
    "moderator": 2,
    "admin": 3,
}

# 熔断器状态
CIRCUIT_CLOSED = "closed"
CIRCUIT_OPEN = "open"
CIRCUIT_HALF_OPEN = "half_open"


@dataclass
class Route:
    pattern: str
    service: str
    priority: int = 0
    permission: Optional[str] = None
    _regex: object = field(default=None, repr=False)
    _param_names: List[str] = field(default_factory=list, repr=False)

    def __post_init__(self):
        # 将 /api/players/{player_id} 编译为正则，并记录参数名
        self._param_names = re.findall(r"\{(\w+)\}", self.pattern)
        regex = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", self.pattern)
        self._regex = re.compile("^" + regex + "$")

    def match(self, path: str) -> Optional[Dict[str, str]]:
        m = self._regex.match(path)
        if not m:
            return None
        return m.groupdict()

    @property
    def specificity(self) -> Tuple[int, int]:
        """静态段越多、参数越少，路由越具体。"""
        segments = [s for s in self.pattern.split("/") if s]
        static_count = sum(1 for s in segments if not (s.startswith("{") and s.endswith("}")))
        return (static_count, -len(self._param_names))


class APIGateway:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

        # 路由表
        self._routes: List[Route] = []

        # 限流配置（令牌桶，按用户独立）
        rl = self.config.get("rate_limit", {})
        self._rl_capacity = rl.get("capacity", 10)
        self._rl_refill_rate = rl.get("refill_rate", 1.0)  # 每秒补充的令牌数
        self._rl_violation_threshold = rl.get("violation_threshold", 3)  # 超限多少次后封禁
        self._rl_ban_duration = rl.get("ban_duration", 60.0)  # 封禁时长（秒）
        # user_id -> {"tokens": float, "last": float, "violations": int, "banned_until": float}
        self._buckets: Dict[str, Dict] = {}

        # 熔断器配置
        cb = self.config.get("circuit_breaker", {})
        self._cb_failure_threshold = cb.get("failure_threshold", 3)  # 连续失败多少次熔断
        self._cb_recovery_timeout = cb.get("recovery_timeout", 30.0)  # 熔断后多久进入半开
        # service -> {"state": str, "failures": int, "opened_at": float}
        self._circuits: Dict[str, Dict] = {}

        # 降级默认响应：service -> 任意默认数据
        self._fallbacks: Dict[str, object] = dict(self.config.get("fallbacks", {}))

        # 认证配置
        auth = self.config.get("auth", {})
        self._token_ttl = auth.get("token_ttl", 3600.0)  # token 有效期（秒）
        # token -> {"user_id": str, "role": str, "expires_at": float}
        self._tokens: Dict[str, Dict] = {}

        self._state = {}
        self._history = []
        # 可注入时钟，便于测试与 update(dt) 推进时间
        self._clock = self.config.get("clock", time.time)

    # ------------------------------------------------------------------
    # 基础
    # ------------------------------------------------------------------
    def _now(self) -> float:
        return self._clock()

    def update(self, dt: float):
        """推进内部时钟（当 config 未提供自定义 clock 时生效）。"""
        if "clock" not in self.config:
            base = self._state.get("virtual_time", time.time())
            self._state["virtual_time"] = base + dt
            self._clock = lambda: self._state["virtual_time"]

    def reset(self):
        self._state = {}
        self._history = []
        self._routes = []
        self._buckets = {}
        self._circuits = {}
        self._tokens = {}

    # ------------------------------------------------------------------
    # 路由
    # ------------------------------------------------------------------
    def add_route(self, pattern: str, service: str, priority: int = 0,
                  permission: Optional[str] = None):
        self._routes.append(Route(pattern=pattern, service=service,
                                  priority=priority, permission=permission))
        # 排序：priority 高的在前；同级时更具体（静态段多、参数少）的在前
        self._routes.sort(key=lambda r: (r.priority, r.specificity), reverse=True)

    def route_request(self, path: str) -> Optional[Dict]:
        """按优先级匹配路由，返回目标服务与路径参数；无匹配返回 None。"""
        for route in self._routes:
            params = route.match(path)
            if params is not None:
                result = {
                    "service": route.service,
                    "pattern": route.pattern,
                    "params": params,
                    "permission": route.permission,
                }
                self._history.append(("route", path, route.service))
                return result
        self._history.append(("route", path, None))
        return None

    # ------------------------------------------------------------------
    # 限流（按用户令牌桶 + 超限惩罚封禁）
    # ------------------------------------------------------------------
    def _get_bucket(self, user_id: str) -> Dict:
        bucket = self._buckets.get(user_id)
        if bucket is None:
            bucket = {
                "tokens": float(self._rl_capacity),
                "last": self._now(),
                "violations": 0,
                "banned_until": 0.0,
            }
            self._buckets[user_id] = bucket
        return bucket

    def is_banned(self, user_id: str) -> bool:
        bucket = self._buckets.get(user_id)
        if not bucket:
            return False
        return self._now() < bucket["banned_until"]

    def rate_limit(self, user_id: str, cost: float = 1.0) -> bool:
        """检查用户是否可调用API。超限累计违规，违规达阈值后封禁一段时间。"""
        now = self._now()
        bucket = self._get_bucket(user_id)

        # 封禁中直接拒绝
        if now < bucket["banned_until"]:
            return False

        # 令牌桶补充
        elapsed = now - bucket["last"]
        bucket["tokens"] = min(self._rl_capacity,
                               bucket["tokens"] + elapsed * self._rl_refill_rate)
        bucket["last"] = now

        if bucket["tokens"] >= cost:
            bucket["tokens"] -= cost
            return True

        # 超限：累计违规，达到阈值则封禁惩罚
        bucket["violations"] += 1
        if bucket["violations"] >= self._rl_violation_threshold:
            bucket["banned_until"] = now + self._rl_ban_duration
            bucket["violations"] = 0
        return False

    # ------------------------------------------------------------------
    # 熔断器（阈值 + 半开状态）
    # ------------------------------------------------------------------
    def _get_circuit(self, service: str) -> Dict:
        circuit = self._circuits.get(service)
        if circuit is None:
            circuit = {"state": CIRCUIT_CLOSED, "failures": 0, "opened_at": 0.0}
            self._circuits[service] = circuit
        return circuit

    def circuit_state(self, service: str) -> str:
        circuit = self._get_circuit(service)
        if circuit["state"] == CIRCUIT_OPEN:
            # 冷却时间到，进入半开
            if self._now() - circuit["opened_at"] >= self._cb_recovery_timeout:
                circuit["state"] = CIRCUIT_HALF_OPEN
        return circuit["state"]

    def circuit_breaker(self, service: str) -> bool:
        """是否允许向该服务转发请求。"""
        return self.circuit_state(service) != CIRCUIT_OPEN

    def record_success(self, service: str):
        circuit = self._get_circuit(service)
        circuit["failures"] = 0
        circuit["state"] = CIRCUIT_CLOSED

    def record_failure(self, service: str):
        circuit = self._get_circuit(service)
        state = self.circuit_state(service)
        if state == CIRCUIT_HALF_OPEN:
            # 半开试探失败，重新熔断
            circuit["state"] = CIRCUIT_OPEN
            circuit["opened_at"] = self._now()
            circuit["failures"] = self._cb_failure_threshold
            return
        circuit["failures"] += 1
        if circuit["failures"] >= self._cb_failure_threshold:
            circuit["state"] = CIRCUIT_OPEN
            circuit["opened_at"] = self._now()

    # ------------------------------------------------------------------
    # 降级（默认值 + 通知）
    # ------------------------------------------------------------------
    def fallback(self, service: str) -> Dict:
        """服务不可用时返回降级响应：默认数据 + 降级通知。"""
        default = self._fallbacks.get(service)
        if default is None:
            default = {}
        return {
            "degraded": True,
            "service": service,
            "data": default,
            "notice": "服务暂时不可用，已切换为降级模式，请稍后再试。",
        }

    # ------------------------------------------------------------------
    # 认证中间件（token 校验 + 权限分级 + 过期）
    # ------------------------------------------------------------------
    def generate_token(self, user_id: str, role: str = "player",
                       expires_in: Optional[float] = None) -> str:
        if role not in ROLE_LEVELS:
            raise ValueError(f"未知角色: {role}")
        ttl = self._token_ttl if expires_in is None else expires_in
        token = uuid.uuid4().hex
        self._tokens[token] = {
            "user_id": user_id,
            "role": role,
            "expires_at": self._now() + ttl,
        }
        return token

    def auth_middleware(self, token: Optional[str],
                        required_role: Optional[str] = None) -> Dict:
        """校验 token。返回 {"ok": bool, ...}，失败时带 reason。"""
        if not token or token not in self._tokens:
            return {"ok": False, "reason": "invalid_token"}

        info = self._tokens[token]
        if self._now() >= info["expires_at"]:
            return {"ok": False, "reason": "token_expired"}

        if required_role is not None:
            user_level = ROLE_LEVELS.get(info["role"], 0)
            required_level = ROLE_LEVELS.get(required_role, math.inf)
            if user_level < required_level:
                return {"ok": False, "reason": "permission_denied"}

        return {"ok": True, "user_id": info["user_id"], "role": info["role"]}
