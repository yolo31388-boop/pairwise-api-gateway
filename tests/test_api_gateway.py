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


class TestAPIGateway:
    def setup_method(self):
        self.system = APIGateway()

    # ---- 路由 ----

    def test_case_01(self):
        """路由：不同路径转发到不同服务"""
        self.system.add_route("/api/shop", "shop-service")
        self.system.add_route("/api/battle", "battle-service")
        assert self.system.route_request("/api/shop").route.service == "shop-service"
        assert self.system.route_request("/api/battle").route.service == "battle-service"

    def test_case_02(self):
        """路由：支持路径参数并解析参数值"""
        self.system.add_route("/api/players/{player_id}", "player-service")
        match = self.system.route_request("/api/players/123")
        assert match is not None
        assert match.route.service == "player-service"
        assert match.params == {"player_id": "123"}

    def test_case_03(self):
        """路由：特定路由优先于通用路由，显式 priority 可覆盖"""
        self.system.add_route("/api/players/{segment}", "generic-service")
        self.system.add_route("/api/players/leaderboard", "leaderboard-service")
        match = self.system.route_request("/api/players/leaderboard")
        assert match.route.service == "leaderboard-service"
        # 显式 priority 更高的通用路由可以覆盖特定路由
        self.system.add_route("/api/items/{item_id}", "generic-items", priority=10)
        self.system.add_route("/api/items/special", "special-items", priority=1)
        assert self.system.route_request("/api/items/special").route.service == "generic-items"

    # ---- 限流 ----

    def test_case_04(self):
        """限流：窗口内超过配额后被拒绝"""
        gateway = APIGateway({"rate_limit": 5, "rate_window": 60.0})
        for _ in range(5):
            assert gateway.rate_limit("u1") is True
        assert gateway.rate_limit("u1") is False

    def test_case_05(self):
        """限流：按用户独立计数，互不影响"""
        gateway = APIGateway({"rate_limit": 2, "rate_window": 60.0})
        assert gateway.rate_limit("u1") is True
        assert gateway.rate_limit("u1") is True
        assert gateway.rate_limit("u1") is False  # u1 超限
        assert gateway.rate_limit("u2") is True   # u2 有独立配额
        assert gateway.rate_limit("u2") is True

    def test_case_06(self):
        """限流：超限后封禁惩罚，重复违规封禁时间加倍"""
        gateway = APIGateway({"rate_limit": 1, "rate_window": 60.0, "ban_duration": 100.0})
        assert gateway.rate_limit("u1") is True
        assert gateway.rate_limit("u1") is False  # 触发封禁
        assert gateway.is_banned("u1") is True
        gateway.update(50.0)
        assert gateway.rate_limit("u1") is False  # 封禁期内仍拒绝
        gateway.update(60.0)  # t=110，封禁结束
        assert gateway.is_banned("u1") is False
        assert gateway.rate_limit("u1") is True
        assert gateway.rate_limit("u1") is False  # 第二次违规，封禁 200 秒
        gateway.update(150.0)  # t=260，距第二次违规 150 秒 < 200
        assert gateway.is_banned("u1") is True

    # ---- 熔断 ----

    def test_case_07(self):
        """熔断：错误率达到阈值后熔断，拒绝转发"""
        gateway = APIGateway({"circuit_error_threshold": 0.5, "circuit_min_requests": 4})
        for _ in range(3):
            gateway.record_result("svc", False)
        assert gateway.circuit_breaker("svc") is True   # 3/3 但样本不足? 样本=3<4
        gateway.record_result("svc", False)             # 4/4 失败，达到阈值
        assert gateway.circuit_state("svc") == "open"
        assert gateway.circuit_breaker("svc") is False

    def test_case_08(self):
        """熔断：错误率未达阈值时不熔断"""
        gateway = APIGateway({"circuit_error_threshold": 0.5, "circuit_min_requests": 4})
        gateway.record_result("svc", True)
        gateway.record_result("svc", True)
        gateway.record_result("svc", False)
        gateway.record_result("svc", True)   # 错误率 1/4 = 25% < 50%
        assert gateway.circuit_state("svc") == "closed"
        assert gateway.circuit_breaker("svc") is True

    def test_case_09(self):
        """熔断：冷却后进入半开，试探成功则恢复，失败则重新熔断"""
        gateway = APIGateway({"circuit_error_threshold": 0.5,
                              "circuit_min_requests": 2, "circuit_cooldown": 30.0})
        gateway.record_result("svc", False)
        gateway.record_result("svc", False)
        assert gateway.circuit_state("svc") == "open"
        gateway.update(31.0)
        assert gateway.circuit_state("svc") == "half_open"
        assert gateway.circuit_breaker("svc") is True   # 允许试探
        gateway.record_result("svc", False)             # 试探失败，重新熔断
        assert gateway.circuit_state("svc") == "open"
        gateway.update(31.0)
        assert gateway.circuit_state("svc") == "half_open"
        assert gateway.circuit_breaker("svc") is True
        gateway.record_result("svc", True)              # 试探成功，恢复
        assert gateway.circuit_state("svc") == "closed"

    # ---- 降级 ----

    def test_case_10(self):
        """降级：服务不可用时返回默认值而不是报错"""
        gateway = APIGateway({"circuit_min_requests": 2})
        gateway.register_fallback("svc", default={"items": [], "cached": True})
        gateway.record_result("svc", False)
        gateway.record_result("svc", False)  # 熔断
        result = gateway.fallback("svc")
        assert result["degraded"] is True
        assert result["data"] == {"items": [], "cached": True}

    def test_case_11(self):
        """降级：产生玩家可见的降级通知"""
        gateway = APIGateway()
        gateway.register_fallback("svc", default={"ok": True})
        result = gateway.fallback("svc")
        assert result["notification"]["type"] == "degraded"
        assert result["notification"]["service"] == "svc"
        notifications = gateway.get_notifications()
        assert len(notifications) == 1
        assert notifications[0]["service"] == "svc"

    # ---- 认证 ----

    def test_case_12(self):
        """认证：无 token 或非法 token 被拒绝，合法 token 通过"""
        ok, ctx, err = self.system.auth_middleware(None)
        assert ok is False and err == "invalid_token"
        ok, ctx, err = self.system.auth_middleware("not-a-token")
        assert ok is False and err == "invalid_token"
        token = self.system.issue_token("u1", role="player")
        ok, ctx, err = self.system.auth_middleware(token)
        assert ok is True and ctx.user_id == "u1" and err is None

    def test_case_13(self):
        """认证：权限分级，普通玩家不能调用管理接口"""
        player_token = self.system.issue_token("u1", role="player")
        admin_token = self.system.issue_token("boss", role="admin")
        ok, ctx, err = self.system.auth_middleware(player_token, required_role="admin")
        assert ok is False and err == "forbidden"
        ok, ctx, err = self.system.auth_middleware(admin_token, required_role="admin")
        assert ok is True
        # 高权限可以访问低权限接口
        ok, ctx, err = self.system.auth_middleware(admin_token, required_role="player")
        assert ok is True

    def test_case_14(self):
        """认证：token 过期后失效"""
        token = self.system.issue_token("u1", role="player", ttl=100.0)
        ok, _, _ = self.system.auth_middleware(token)
        assert ok is True
        self.system.update(101.0)
        ok, ctx, err = self.system.auth_middleware(token)
        assert ok is False and err == "invalid_token"

    # ---- 端到端 ----

    def test_case_15(self):
        """端到端：认证+路由+转发，路径参数透传给后端"""
        gateway = APIGateway()
        gateway.add_route("/api/players/{player_id}", "player-service", min_role="player")
        gateway.register_service("player-service",
                                 lambda req: {"player": req["params"]["player_id"]})
        token = gateway.issue_token("u1", role="player")
        resp = gateway.handle_request("/api/players/123", token=token)
        assert resp["status"] == 200
        assert resp["data"] == {"player": "123"}
        # 未认证请求被拒绝
        resp = gateway.handle_request("/api/players/123")
        assert resp["status"] == 401

    def test_case_16(self):
        """端到端：后端连续异常触发熔断，后续请求走降级并通知"""
        gateway = APIGateway({"circuit_error_threshold": 0.5, "circuit_min_requests": 2})
        gateway.add_route("/api/shop", "shop-service", min_role="player")
        gateway.register_fallback("shop-service", default={"items": [], "cached": True})

        def broken_handler(req):
            raise RuntimeError("backend down")

        gateway.register_service("shop-service", broken_handler)
        token = gateway.issue_token("u1", role="player")
        gateway.handle_request("/api/shop", token=token)   # 失败 1
        gateway.handle_request("/api/shop", token=token)   # 失败 2 -> 熔断
        assert gateway.circuit_state("shop-service") == "open"
        resp = gateway.handle_request("/api/shop", token=token)
        assert resp["degraded"] is True
        assert resp["data"] == {"items": [], "cached": True}
        assert resp["notification"]["service"] == "shop-service"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
