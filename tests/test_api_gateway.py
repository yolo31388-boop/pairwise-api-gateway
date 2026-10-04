"""
游戏内API网关与限流熔断系统 - 验收测试
运行方式：python -m pytest tests/test_api_gateway.py -q
共 16 个测试用例
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.api_gateway import APIGateway


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, dt):
        self.now += dt


def make_gateway(**overrides):
    clock = FakeClock()
    config = {
        "clock": clock,
        "rate_limit": {
            "capacity": 5,
            "refill_rate": 1.0,
            "violation_threshold": 3,
            "ban_duration": 60.0,
        },
        "circuit_breaker": {
            "failure_threshold": 3,
            "recovery_timeout": 30.0,
        },
        "fallbacks": {
            "player-service": {"players": [], "cached": True},
        },
        "auth": {"token_ttl": 100.0},
    }
    config.update(overrides)
    gw = APIGateway(config)
    return gw, clock


def build_routes(gw):
    gw.add_route("/api/players/{player_id}", "player-service", priority=10)
    gw.add_route("/api/players/{player_id}/inventory", "inventory-service", priority=20)
    gw.add_route("/api/admin/players", "admin-service", priority=30, permission="admin")
    gw.add_route("/api/{resource}", "generic-service", priority=0)


class TestAPIGateway:
    def setup_method(self):
        self.system, self.clock = make_gateway()
        build_routes(self.system)

    # ---------------- 路由 ----------------
    def test_case_01(self):
        """路由分发：不同路径转发到不同服务，而不是全部发到同一个服务"""
        r1 = self.system.route_request("/api/admin/players")
        r2 = self.system.route_request("/api/players/7/inventory")
        assert r1["service"] == "admin-service"
        assert r2["service"] == "inventory-service"
        assert r1["service"] != r2["service"]

    def test_case_02(self):
        """路由支持路径参数：/api/players/123 能匹配并提取参数"""
        result = self.system.route_request("/api/players/123")
        assert result is not None
        assert result["service"] == "player-service"
        assert result["params"] == {"player_id": "123"}

    def test_case_03(self):
        """路由优先级：特定路由优先于通用路由，不被 /api/{resource} 覆盖"""
        result = self.system.route_request("/api/players")
        assert result["service"] == "generic-service"  # 只有通用路由能匹配
        specific = self.system.route_request("/api/players/123")
        assert specific["service"] == "player-service"  # 特定路由优先命中

    def test_case_04(self):
        """无匹配路由时返回 None，而不是错误转发"""
        assert self.system.route_request("/unknown/path") is None

    # ---------------- 限流 ----------------
    def test_case_05(self):
        """限流生效：超过限额后请求被拒绝，不能无限刷API"""
        allowed = [self.system.rate_limit("user1") for _ in range(5)]
        assert all(allowed)
        assert self.system.rate_limit("user1") is False

    def test_case_06(self):
        """限流按用户独立：一个用户超限不影响其他用户"""
        for _ in range(5):
            self.system.rate_limit("user1")
        assert self.system.rate_limit("user1") is False
        assert self.system.rate_limit("user2") is True

    def test_case_07(self):
        """限流惩罚：连续超限达到阈值后被封禁，补充令牌后仍被拒绝"""
        for _ in range(5):
            self.system.rate_limit("user1")
        # 连续超限 3 次触发封禁
        assert self.system.rate_limit("user1") is False
        assert self.system.rate_limit("user1") is False
        assert self.system.rate_limit("user1") is False
        assert self.system.is_banned("user1") is True
        # 封禁期间即使令牌已补充也拒绝
        self.clock.advance(10)
        assert self.system.rate_limit("user1") is False
        # 封禁结束后恢复
        self.clock.advance(60)
        assert self.system.rate_limit("user1") is True

    def test_case_08(self):
        """令牌桶补充：随时间恢复调用能力"""
        for _ in range(5):
            self.system.rate_limit("user1")
        assert self.system.rate_limit("user1") is False
        self.clock.advance(2)  # 补充 2 个令牌
        assert self.system.rate_limit("user1") is True
        assert self.system.rate_limit("user1") is True
        assert self.system.rate_limit("user1") is False

    # ---------------- 熔断 ----------------
    def test_case_09(self):
        """熔断阈值：连续失败达到阈值后熔断，不再转发请求"""
        svc = "player-service"
        assert self.system.circuit_breaker(svc) is True
        for _ in range(3):
            self.system.record_failure(svc)
        assert self.system.circuit_state(svc) == "open"
        assert self.system.circuit_breaker(svc) is False

    def test_case_10(self):
        """熔断半开恢复：冷却后进半开，试探成功后恢复闭合"""
        svc = "player-service"
        for _ in range(3):
            self.system.record_failure(svc)
        assert self.system.circuit_breaker(svc) is False
        self.clock.advance(30)  # 冷却结束
        assert self.system.circuit_state(svc) == "half_open"
        assert self.system.circuit_breaker(svc) is True  # 半开放行试探请求
        self.system.record_success(svc)
        assert self.system.circuit_state(svc) == "closed"

    def test_case_11(self):
        """半开试探失败重新熔断；成功请求重置失败计数"""
        svc = "player-service"
        for _ in range(3):
            self.system.record_failure(svc)
        self.clock.advance(30)
        assert self.system.circuit_state(svc) == "half_open"
        self.system.record_failure(svc)  # 试探失败
        assert self.system.circuit_state(svc) == "open"
        # 成功会重置连续失败计数
        self.system.record_success(svc)
        self.system.record_failure(svc)
        self.system.record_failure(svc)
        assert self.system.circuit_state(svc) == "closed"

    # ---------------- 降级 ----------------
    def test_case_12(self):
        """降级默认值：服务挂了返回配置的默认数据而不是报错/空响应"""
        result = self.system.fallback("player-service")
        assert result["degraded"] is True
        assert result["data"] == {"players": [], "cached": True}
        # 未配置默认值的服务也返回安全默认（空dict）而非 None
        result2 = self.system.fallback("unknown-service")
        assert result2["data"] == {}

    def test_case_13(self):
        """降级通知：响应携带通知，玩家能感知服务降级"""
        result = self.system.fallback("player-service")
        assert result["degraded"] is True
        assert result["notice"]
        assert "降级" in result["notice"]

    # ---------------- 认证 ----------------
    def test_case_14(self):
        """认证校验：无token/伪造token被拒绝，合法token放行"""
        assert self.system.auth_middleware(None)["ok"] is False
        assert self.system.auth_middleware("fake-token")["ok"] is False
        token = self.system.generate_token("user1", role="player")
        result = self.system.auth_middleware(token)
        assert result["ok"] is True
        assert result["user_id"] == "user1"

    def test_case_15(self):
        """权限分级：普通玩家不能调用管理接口，管理员可以"""
        player_token = self.system.generate_token("user1", role="player")
        admin_token = self.system.generate_token("boss", role="admin")
        denied = self.system.auth_middleware(player_token, required_role="admin")
        assert denied["ok"] is False
        assert denied["reason"] == "permission_denied"
        assert self.system.auth_middleware(admin_token, required_role="admin")["ok"] is True
        # 高权限可访问低权限接口
        assert self.system.auth_middleware(admin_token, required_role="player")["ok"] is True

    def test_case_16(self):
        """token过期：过期后被拒绝，未过期前可用"""
        token = self.system.generate_token("user1", role="player", expires_in=50)
        assert self.system.auth_middleware(token)["ok"] is True
        self.clock.advance(60)
        result = self.system.auth_middleware(token)
        assert result["ok"] is False
        assert result["reason"] == "token_expired"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
