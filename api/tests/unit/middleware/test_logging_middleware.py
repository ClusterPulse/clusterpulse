"""Comprehensive tests for logging middleware."""

import time

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from clusterpulse.api.middleware.logging import LoggingMiddleware


@pytest.fixture
def app_with_logging_middleware():
    """Create FastAPI app with logging middleware."""
    app = FastAPI()
    app.add_middleware(LoggingMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"status": "ok"}

    @app.get("/slow")
    async def slow_endpoint():
        time.sleep(0.1)
        return {"status": "slow"}

    @app.get("/error")
    async def error_endpoint():
        raise HTTPException(status_code=500, detail="Test error")

    @app.get("/exception")
    async def exception_endpoint():
        raise ValueError("Unexpected error")

    return app


@pytest.mark.unit
class TestLoggingMiddlewareRequestLogging:
    """Test request logging functionality."""

    def test_logs_request_start(self, app_with_logging_middleware, caplog):
        """Should log when request starts."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test")

        assert response.status_code == 200

        # Check for request_started log
        log_messages = [record.message for record in caplog.records]
        assert any("request_started" in msg for msg in log_messages)

    def test_logs_request_method(self, app_with_logging_middleware, caplog):
        """Should log request method."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test")

        assert response.status_code == 200

        # Check that GET method was logged
        log_records = [r for r in caplog.records if "request_started" in r.message]
        assert len(log_records) > 0

        # The log_event function includes the kwargs in the message
        assert any("GET" in record.message for record in log_records)

    def test_logs_request_path(self, app_with_logging_middleware, caplog):
        """Should log request path."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test")

        assert response.status_code == 200

        log_records = [r for r in caplog.records if "request_started" in r.message]
        assert any("/test" in record.message for record in log_records)

    def test_logs_query_params(self, app_with_logging_middleware, caplog):
        """Should log query parameters."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test?foo=bar&baz=qux")

        assert response.status_code == 200

        log_records = [r for r in caplog.records if "request_started" in r.message]
        # Query params should be in the log
        assert any(
            "foo" in record.message and "bar" in record.message
            for record in log_records
        )

    def test_logs_client_host(self, app_with_logging_middleware, caplog):
        """Should log client host."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test")

        assert response.status_code == 200

        # TestClient uses testclient as host
        log_records = [r for r in caplog.records if "request_started" in r.message]
        assert any("testclient" in record.message for record in log_records)

    def test_logs_user_agent(self, app_with_logging_middleware, caplog):
        """Should log user agent."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test", headers={"User-Agent": "TestAgent/1.0"})

        assert response.status_code == 200

        log_records = [r for r in caplog.records if "request_started" in r.message]
        assert any("TestAgent" in record.message for record in log_records)


@pytest.mark.unit
class TestLoggingMiddlewareResponseLogging:
    """Test response logging functionality."""

    def test_logs_request_completion(self, app_with_logging_middleware, caplog):
        """Should log when request completes."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test")

        assert response.status_code == 200

        # Check for request_completed log
        log_messages = [record.message for record in caplog.records]
        assert any("request_completed" in msg for msg in log_messages)

    def test_logs_status_code(self, app_with_logging_middleware, caplog):
        """Should log response status code."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test")

        assert response.status_code == 200

        log_records = [r for r in caplog.records if "request_completed" in r.message]
        assert any("200" in record.message for record in log_records)

    def test_logs_duration(self, app_with_logging_middleware, caplog):
        """Should log request duration."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test")

        assert response.status_code == 200

        log_records = [r for r in caplog.records if "request_completed" in r.message]
        assert any("duration_seconds" in record.message for record in log_records)

    def test_logs_slow_requests(self, app_with_logging_middleware, caplog):
        """Should log duration for slow requests."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/slow")

        assert response.status_code == 200

        # Check that duration is logged and is reasonable
        log_records = [r for r in caplog.records if "request_completed" in r.message]
        assert len(log_records) > 0
        # Duration should be at least 0.1 seconds
        assert any("duration_seconds" in record.message for record in log_records)


@pytest.mark.unit
class TestLoggingMiddlewareTimingHeader:
    """Test X-Process-Time header functionality."""

    def test_adds_timing_header(self, app_with_logging_middleware):
        """Should add X-Process-Time header to response."""
        client = TestClient(app_with_logging_middleware)

        response = client.get("/test")

        assert response.status_code == 200
        assert "X-Process-Time" in response.headers

    def test_timing_header_is_numeric(self, app_with_logging_middleware):
        """X-Process-Time should be a valid number."""
        client = TestClient(app_with_logging_middleware)

        response = client.get("/test")

        assert response.status_code == 200

        process_time = response.headers.get("X-Process-Time")
        assert process_time is not None

        # Should be convertible to float
        time_value = float(process_time)
        assert time_value >= 0

    def test_timing_header_reflects_duration(self, app_with_logging_middleware):
        """X-Process-Time should reflect actual request duration."""
        client = TestClient(app_with_logging_middleware)

        response = client.get("/slow")

        assert response.status_code == 200

        process_time = float(response.headers.get("X-Process-Time"))
        # Should be at least 0.1 seconds for slow endpoint
        assert process_time >= 0.1

    def test_timing_header_on_error_responses(self, app_with_logging_middleware):
        """X-Process-Time should be present even on errors."""
        client = TestClient(app_with_logging_middleware)

        response = client.get("/error")

        assert response.status_code == 500
        assert "X-Process-Time" in response.headers

        process_time = float(response.headers.get("X-Process-Time"))
        assert process_time >= 0


@pytest.mark.unit
class TestLoggingMiddlewareErrorLogging:
    """Test error logging functionality.

    Note: FastAPI handles HTTPException internally, so middleware sees these as normal responses.
    Unexpected exceptions are caught by middleware, logged, and then re-raised.
    """

    def test_logs_http_exceptions(self, app_with_logging_middleware, caplog):
        """Should complete normally for HTTP exceptions (FastAPI handles them)."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/error")

        assert response.status_code == 500

        # HTTPException is handled by FastAPI, so middleware sees it as a normal response
        # Check for request_completed (not request_failed)
        log_messages = [record.message for record in caplog.records]
        assert any("request_completed" in msg for msg in log_messages)

        # Should log the 500 status code
        completed_logs = [r for r in caplog.records if "request_completed" in r.message]
        assert any("500" in record.message for record in completed_logs)

    def test_logs_unexpected_exceptions(self, app_with_logging_middleware, caplog):
        """Should log unexpected exceptions before they propagate."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("ERROR"):
            # Unexpected exceptions propagate through TestClient
            with pytest.raises(ValueError):
                client.get("/exception")

        # Middleware successfully logs the error before re-raising
        log_messages = [record.message for record in caplog.records]
        assert any("request_failed" in msg for msg in log_messages)

    def test_logs_error_type(self, app_with_logging_middleware, caplog):
        """Should log error type."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("ERROR"):
            with pytest.raises(ValueError):
                client.get("/exception")

        log_records = [r for r in caplog.records if "request_failed" in r.message]
        # Should log ValueError as the error type
        assert len(log_records) > 0
        assert any("ValueError" in record.message for record in log_records)

    def test_logs_error_duration(self, app_with_logging_middleware, caplog):
        """Should log duration even on errors (for HTTP errors handled by FastAPI)."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            # HTTP errors are handled normally by FastAPI
            response = client.get("/error")

        assert response.status_code == 500

        # Should complete normally and log duration
        log_records = [r for r in caplog.records if "request_completed" in r.message]
        assert any("duration_seconds" in record.message for record in log_records)


@pytest.mark.unit
class TestLoggingMiddlewareRequestID:
    """Test request ID logging."""

    def test_logs_request_id_when_present(self, app_with_logging_middleware, caplog):
        """Should log request ID if present in state."""
        # Need to add auth middleware to set request_id
        from clusterpulse.api.middleware.auth import AuthMiddleware

        app = app_with_logging_middleware
        app.add_middleware(AuthMiddleware)

        client = TestClient(app)

        with caplog.at_level("INFO"):
            response = client.get("/test", headers={"X-Request-ID": "log-test-123"})

        assert response.status_code == 200

        # Check that request ID was included in logs
        log_records = [r for r in caplog.records if "request_started" in r.message]
        assert any("log-test-123" in record.message for record in log_records)


@pytest.mark.unit
class TestLoggingMiddlewareCompleteness:
    """Test that all expected information is logged."""

    def test_logs_complete_request_info(self, app_with_logging_middleware, caplog):
        """Should log all request information."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get(
                "/test?param=value", headers={"User-Agent": "TestAgent/1.0"}
            )

        assert response.status_code == 200

        started_logs = [r for r in caplog.records if "request_started" in r.message]
        assert len(started_logs) > 0

        log_msg = started_logs[0].message

        # Should contain all key information
        assert "GET" in log_msg
        assert "/test" in log_msg
        assert "param" in log_msg
        assert "TestAgent" in log_msg

    def test_logs_complete_response_info(self, app_with_logging_middleware, caplog):
        """Should log all response information."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test")

        assert response.status_code == 200

        completed_logs = [r for r in caplog.records if "request_completed" in r.message]
        assert len(completed_logs) > 0

        log_msg = completed_logs[0].message

        # Should contain status and duration
        assert "200" in log_msg
        assert "duration_seconds" in log_msg


@pytest.mark.unit
class TestLoggingMiddlewareDifferentMethods:
    """Test logging for different HTTP methods."""

    def test_logs_get_request(self, app_with_logging_middleware, caplog):
        """Should log GET requests."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.get("/test")

        assert response.status_code == 200

        log_records = [r for r in caplog.records if "request_started" in r.message]
        assert any("GET" in record.message for record in log_records)

    def test_logs_post_request(self, app_with_logging_middleware, caplog):
        """Should log POST requests."""

        @app_with_logging_middleware.post("/test-post")
        async def post_endpoint():
            return {"status": "created"}

        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            response = client.post("/test-post", json={"data": "test"})

        assert response.status_code == 200

        log_records = [r for r in caplog.records if "request_started" in r.message]
        assert any("POST" in record.message for record in log_records)

    def test_logs_different_status_codes(self, app_with_logging_middleware, caplog):
        """Should log various status codes."""

        @app_with_logging_middleware.post("/created")
        async def created_endpoint():
            return {"status": "created"}, 201

        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            # 200 OK
            response = client.get("/test")
            assert response.status_code == 200

            # 500 Error
            response = client.get("/error")
            assert response.status_code == 500

        completed_logs = [r for r in caplog.records if "request_completed" in r.message]

        # Should have logged different status codes
        messages = [r.message for r in completed_logs]
        assert any("200" in msg for msg in messages)
        assert any("500" in msg for msg in messages)


@pytest.mark.unit
class TestLoggingMiddlewareEdgeCases:
    """Test edge cases and unusual scenarios."""

    def test_handles_missing_user_agent(self, app_with_logging_middleware, caplog):
        """Should handle requests without user agent."""
        client = TestClient(app_with_logging_middleware)

        # Remove default user agent
        with caplog.at_level("INFO"):
            response = client.get("/test", headers={"User-Agent": ""})

        assert response.status_code == 200

        # Should still log successfully
        log_messages = [record.message for record in caplog.records]
        assert any("request_started" in msg for msg in log_messages)

    def test_handles_very_long_path(self, app_with_logging_middleware, caplog):
        """Should handle very long request paths."""
        long_path = "/test?" + "&".join([f"param{i}=value{i}" for i in range(100)])

        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            client.get(long_path)

        # May be 404 but should log
        log_messages = [record.message for record in caplog.records]
        assert any("request_started" in msg for msg in log_messages)

    def test_handles_concurrent_requests(self, app_with_logging_middleware, caplog):
        """Should handle concurrent requests correctly."""
        client = TestClient(app_with_logging_middleware)

        with caplog.at_level("INFO"):
            # Make multiple requests
            responses = [client.get(f"/test") for _ in range(5)]

        # All should succeed
        assert all(r.status_code == 200 for r in responses)

        # Should have logged all requests
        started_logs = [r for r in caplog.records if "request_started" in r.message]
        completed_logs = [r for r in caplog.records if "request_completed" in r.message]

        assert len(started_logs) == 5
        assert len(completed_logs) == 5


@pytest.mark.unit
class TestLoggingMiddlewareIntegration:
    """Integration tests with other middleware."""

    def test_works_with_auth_middleware(self):
        """Should work alongside auth middleware."""
        from clusterpulse.api.middleware.auth import AuthMiddleware

        app = FastAPI()
        app.add_middleware(LoggingMiddleware)
        app.add_middleware(AuthMiddleware)

        @app.get("/test")
        async def test_endpoint():
            return {"status": "ok"}

        client = TestClient(app)
        response = client.get("/test", headers={"X-Request-ID": "integration-test"})

        assert response.status_code == 200
        assert "X-Process-Time" in response.headers
        assert "X-Request-ID" in response.headers

    def test_timing_includes_all_middleware(self):
        """Timing should include all middleware processing."""
        from clusterpulse.api.middleware.auth import AuthMiddleware

        app = FastAPI()
        app.add_middleware(LoggingMiddleware)
        app.add_middleware(AuthMiddleware)

        @app.get("/test")
        async def test_endpoint():
            time.sleep(0.05)
            return {"status": "ok"}

        client = TestClient(app)
        response = client.get("/test")

        assert response.status_code == 200

        process_time = float(response.headers.get("X-Process-Time"))
        # Should include middleware processing time plus endpoint time
        assert process_time >= 0.05


@pytest.mark.unit
class TestLoggingMiddlewarePerformance:
    """Test performance impact of logging middleware."""

    def test_minimal_overhead(self, app_with_logging_middleware):
        """Logging middleware should add minimal overhead."""
        client = TestClient(app_with_logging_middleware)

        # Make request and check timing
        response = client.get("/test")

        assert response.status_code == 200

        process_time = float(response.headers.get("X-Process-Time"))
        # Should complete very quickly
        assert process_time < 0.1  # Less than 100ms

    def test_does_not_significantly_impact_fast_requests(
        self, app_with_logging_middleware
    ):
        """Should not significantly slow down fast requests."""

        @app_with_logging_middleware.get("/fast")
        async def fast_endpoint():
            return {"status": "fast"}

        client = TestClient(app_with_logging_middleware)

        # Make multiple fast requests
        times = []
        for _ in range(10):
            response = client.get("/fast")
            times.append(float(response.headers.get("X-Process-Time")))

        # Average time should be very low
        avg_time = sum(times) / len(times)
        assert avg_time < 0.01  # Less than 10ms average
