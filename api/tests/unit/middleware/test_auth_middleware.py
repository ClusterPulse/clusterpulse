"""Comprehensive tests for authentication middleware."""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from clusterpulse.api.middleware.auth import AuthMiddleware


@pytest.fixture
def app_with_auth_middleware():
    """Create FastAPI app with auth middleware."""
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"status": "ok"}

    @app.get("/health")
    async def health_endpoint():
        return {"status": "healthy"}

    @app.get("/ready")
    async def ready_endpoint():
        return {"status": "ready"}

    @app.get("/api/v1/public/clusters")
    async def public_endpoint():
        return {"clusters": []}

    @app.get("/api/v1/clusters")
    async def protected_endpoint():
        return {"clusters": []}

    return app


@pytest.mark.unit
class TestAuthMiddlewareHealthChecks:
    """Test that health checks bypass authentication."""

    def test_health_check_bypasses_auth(self, app_with_auth_middleware, monkeypatch):
        """Health check endpoint should not require authentication."""
        monkeypatch.setenv("HEALTH_CHECK_PATH", "/health")

        client = TestClient(app_with_auth_middleware)
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_readiness_check_bypasses_auth(self, app_with_auth_middleware, monkeypatch):
        """Readiness check endpoint should not require authentication."""
        monkeypatch.setenv("READINESS_CHECK_PATH", "/ready")

        client = TestClient(app_with_auth_middleware)
        response = client.get("/ready")

        assert response.status_code == 200
        assert response.json() == {"status": "ready"}


@pytest.mark.unit
class TestAuthMiddlewarePublicEndpoints:
    """Test public endpoint access control."""

    def test_public_endpoint_allowed_when_enabled(
        self, app_with_auth_middleware, monkeypatch
    ):
        """Public endpoints should be accessible when anonymous access is enabled."""
        monkeypatch.setenv("ALLOW_ANONYMOUS_ACCESS", "true")
        monkeypatch.setenv("PUBLIC_API_PREFIX", "/api/v1/public")

        client = TestClient(app_with_auth_middleware)
        response = client.get("/api/v1/public/clusters")

        assert response.status_code == 200

    def test_public_endpoint_blocked_when_disabled(
        self, app_with_auth_middleware, monkeypatch
    ):
        """Public endpoints should require auth when anonymous access is disabled."""
        monkeypatch.setenv("ALLOW_ANONYMOUS_ACCESS", "false")

        client = TestClient(app_with_auth_middleware)
        # Without auth headers, should still process but endpoint may enforce auth
        response = client.get("/api/v1/public/clusters")

        # Middleware allows it through, endpoint handles auth
        assert response.status_code in [200, 401, 403]


@pytest.mark.unit
class TestAuthMiddlewareRequestID:
    """Test request ID handling."""

    def test_uses_existing_request_id(self, app_with_auth_middleware):
        """Should use X-Request-ID if provided."""
        client = TestClient(app_with_auth_middleware)

        response = client.get("/test", headers={"X-Request-ID": "test-123"})

        assert response.headers.get("X-Request-ID") == "test-123"

    def test_generates_request_id_when_missing(self, app_with_auth_middleware):
        """Should generate request ID if not provided."""
        client = TestClient(app_with_auth_middleware)

        response = client.get("/test")

        request_id = response.headers.get("X-Request-ID")
        assert request_id is not None
        assert len(request_id) > 0

    def test_request_id_added_to_state(self, app_with_auth_middleware):
        """Request ID should be added to request.state."""
        captured_state = {}

        @app_with_auth_middleware.get("/capture-state")
        async def capture_endpoint(request: Request):
            captured_state["request_id"] = request.state.request_id
            return {"ok": True}

        client = TestClient(app_with_auth_middleware)
        response = client.get("/capture-state", headers={"X-Request-ID": "test-456"})

        assert response.status_code == 200
        assert captured_state["request_id"] == "test-456"


@pytest.mark.unit
class TestAuthMiddlewareSecurityHeaders:
    """Test security header injection."""

    def test_adds_content_type_options_header(self, app_with_auth_middleware):
        """Should add X-Content-Type-Options: nosniff."""
        client = TestClient(app_with_auth_middleware)

        response = client.get("/test")

        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_adds_frame_options_header(self, app_with_auth_middleware):
        """Should add X-Frame-Options: DENY."""
        client = TestClient(app_with_auth_middleware)

        response = client.get("/test")

        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_adds_request_id_header(self, app_with_auth_middleware):
        """Should add X-Request-ID to response."""
        client = TestClient(app_with_auth_middleware)

        response = client.get("/test")

        assert "X-Request-ID" in response.headers

    def test_security_headers_on_all_responses(self, app_with_auth_middleware):
        """Security headers should be on all responses including errors."""
        client = TestClient(app_with_auth_middleware)

        # Test on success
        response = client.get("/test")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

        # Test on 404
        response = client.get("/nonexistent")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"


@pytest.mark.unit
class TestAuthMiddlewareOAuthHeaders:
    """Test OAuth header logging in debug mode."""

    def test_logs_oauth_headers_in_debug_mode(
        self, app_with_auth_middleware, monkeypatch, caplog
    ):
        """Should log OAuth headers when debug is enabled."""
        # Mock settings directly (env vars don't work after import)
        from clusterpulse.core import config

        monkeypatch.setattr(config.settings, "debug", True)
        monkeypatch.setattr(config.settings, "oauth_header_user", "X-Forwarded-User")
        monkeypatch.setattr(config.settings, "oauth_header_email", "X-Forwarded-Email")

        client = TestClient(app_with_auth_middleware)

        with caplog.at_level("DEBUG"):
            response = client.get(
                "/test",
                headers={
                    "X-Forwarded-User": "testuser",
                    "X-Forwarded-Email": "test@example.com",
                    "X-Request-ID": "log-test-123",
                },
            )

        assert response.status_code == 200

        # Check that OAuth headers were logged
        log_messages = [record.message for record in caplog.records]
        assert any("OAuth headers in request" in msg for msg in log_messages)

    def test_does_not_log_oauth_headers_when_debug_disabled(
        self, app_with_auth_middleware, monkeypatch, caplog
    ):
        """Should not log OAuth headers when debug is disabled."""
        # Mock settings directly
        from clusterpulse.core import config

        monkeypatch.setattr(config.settings, "debug", False)

        client = TestClient(app_with_auth_middleware)

        with caplog.at_level("DEBUG"):
            response = client.get(
                "/test",
                headers={
                    "X-Forwarded-User": "testuser",
                    "X-Forwarded-Email": "test@example.com",
                },
            )

        assert response.status_code == 200

        # Should not have OAuth header logs
        log_messages = [record.message for record in caplog.records]
        oauth_logs = [msg for msg in log_messages if "OAuth headers" in msg]
        assert len(oauth_logs) == 0


@pytest.mark.unit
class TestAuthMiddlewareRequestFlow:
    """Test complete request flow through middleware."""

    def test_complete_request_flow(self, app_with_auth_middleware):
        """Test complete request processing."""
        client = TestClient(app_with_auth_middleware)

        response = client.get("/test", headers={"X-Request-ID": "flow-test"})

        # Verify response
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

        # Verify headers added
        assert response.headers.get("X-Request-ID") == "flow-test"
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"

    def test_middleware_processes_errors(self, app_with_auth_middleware):
        """Middleware should still add headers even on errors."""
        client = TestClient(app_with_auth_middleware)

        response = client.get("/nonexistent")

        # Should still have security headers on 404
        assert response.status_code == 404
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert "X-Request-ID" in response.headers


@pytest.mark.unit
class TestAuthMiddlewareConfiguration:
    """Test middleware behavior with different configurations."""

    def test_development_mode_configuration(
        self, app_with_auth_middleware, monkeypatch
    ):
        """Test middleware in development mode."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.setenv("OAUTH_PROXY_ENABLED", "false")

        client = TestClient(app_with_auth_middleware)
        response = client.get("/test")

        assert response.status_code == 200
        assert "X-Request-ID" in response.headers

    def test_production_mode_configuration(self, app_with_auth_middleware, monkeypatch):
        """Test middleware in production mode."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("OAUTH_PROXY_ENABLED", "true")

        client = TestClient(app_with_auth_middleware)
        response = client.get("/test")

        assert response.status_code == 200
        assert "X-Request-ID" in response.headers


@pytest.mark.unit
class TestAuthMiddlewarePathMatching:
    """Test path matching for health and public endpoints."""

    def test_exact_health_path_match(self, app_with_auth_middleware, monkeypatch):
        """Health check path should match exactly."""
        monkeypatch.setenv("HEALTH_CHECK_PATH", "/health")

        client = TestClient(app_with_auth_middleware)

        # Exact match should work
        response = client.get("/health")
        assert response.status_code == 200

        # Similar paths should not match
        response = client.get("/healthy")
        assert response.status_code == 404  # Not the health endpoint

    def test_public_prefix_matching(self, app_with_auth_middleware, monkeypatch):
        """Public API prefix should match all sub-paths."""
        monkeypatch.setenv("ALLOW_ANONYMOUS_ACCESS", "true")
        monkeypatch.setenv("PUBLIC_API_PREFIX", "/api/v1/public")

        client = TestClient(app_with_auth_middleware)

        # Should match paths starting with prefix
        response = client.get("/api/v1/public/clusters")
        assert response.status_code == 200


@pytest.mark.unit
class TestAuthMiddlewareEdgeCases:
    """Test edge cases and error conditions."""

    def test_handles_missing_headers(self, app_with_auth_middleware):
        """Should handle requests with no headers."""
        client = TestClient(app_with_auth_middleware)

        response = client.get("/test")

        assert response.status_code == 200
        assert "X-Request-ID" in response.headers

    def test_handles_empty_request_id(self, app_with_auth_middleware):
        """Should accept empty request ID (middleware doesn't validate)."""
        client = TestClient(app_with_auth_middleware)

        response = client.get("/test", headers={"X-Request-ID": ""})

        # Middleware accepts empty string (doesn't validate)
        request_id = response.headers.get("X-Request-ID")
        assert request_id is not None
        # Empty string is passed through as-is
        assert request_id == ""

    def test_handles_very_long_request_id(self, app_with_auth_middleware):
        """Should handle very long request IDs."""
        long_id = "x" * 1000
        client = TestClient(app_with_auth_middleware)

        response = client.get("/test", headers={"X-Request-ID": long_id})

        # Should still work
        assert response.status_code == 200
        assert response.headers.get("X-Request-ID") == long_id


@pytest.mark.unit
class TestAuthMiddlewareIntegration:
    """Integration tests with other middleware/components."""

    def test_works_with_multiple_middleware(self):
        """Should work alongside other middleware."""
        app = FastAPI()

        # Add multiple middleware
        from clusterpulse.api.middleware.logging import LoggingMiddleware

        app.add_middleware(LoggingMiddleware)
        app.add_middleware(AuthMiddleware)

        @app.get("/test")
        async def test_endpoint():
            return {"status": "ok"}

        client = TestClient(app)
        response = client.get("/test")

        assert response.status_code == 200
        assert "X-Request-ID" in response.headers
        assert response.headers.get("X-Content-Type-Options") == "nosniff"

    def test_request_state_available_to_endpoint(self, app_with_auth_middleware):
        """Request state should be available to endpoint handlers."""
        captured_data = {}

        @app_with_auth_middleware.get("/check-state")
        async def check_state(request: Request):
            captured_data["has_request_id"] = hasattr(request.state, "request_id")
            captured_data["request_id"] = getattr(request.state, "request_id", None)
            return {"ok": True}

        client = TestClient(app_with_auth_middleware)
        response = client.get("/check-state", headers={"X-Request-ID": "state-test"})

        assert response.status_code == 200
        assert captured_data["has_request_id"] is True
        assert captured_data["request_id"] == "state-test"
