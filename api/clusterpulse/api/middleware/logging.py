"""Logging middleware for request/response tracking."""

import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from clusterpulse.core.logging import get_logger, log_event

logger = get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging requests and responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request and response information."""
        start_time = time.time()

        # Extract request info
        request_info = {
            "method": request.method,
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "client_host": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }

        # Add request ID if available
        if hasattr(request.state, "request_id"):
            request_info["request_id"] = request.state.request_id

        # Log request
        log_event(logger, "info", "request_started", **request_info)

        try:
            # Process request
            response = await call_next(request)

            # Calculate duration
            duration = time.time() - start_time

            # Log response
            log_event(
                logger,
                "info",
                "request_completed",
                status_code=response.status_code,
                duration_seconds=duration,
                **request_info,
            )

            # Add timing header
            response.headers["X-Process-Time"] = str(duration)

            return response

        except Exception as e:
            # Log error
            duration = time.time() - start_time
            log_event(
                logger,
                "error",
                "request_failed",
                error=str(e),
                error_type=type(e).__name__,
                duration_seconds=duration,
                **request_info,
            )
            raise
