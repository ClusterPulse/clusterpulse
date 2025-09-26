"""Authentication middleware for request processing."""

import time
from typing import Callable

from fastapi import Request, Response
from src.core.config import settings
from src.core.logging import get_logger
from starlette.middleware.base import BaseHTTPMiddleware

logger = get_logger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware for handling authentication concerns."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request for authentication."""
        # Skip auth for health check endpoints
        if request.url.path in [
            settings.health_check_path,
            settings.readiness_check_path,
        ]:
            return await call_next(request)

        # Add request ID for tracing
        request_id = request.headers.get("X-Request-ID", f"{time.time()}")
        request.state.request_id = request_id

        # Log OAuth headers if in debug mode (simplified - no groups)
        if settings.debug:
            oauth_headers = {
                settings.oauth_header_user: request.headers.get(
                    settings.oauth_header_user
                ),
                settings.oauth_header_email: request.headers.get(
                    settings.oauth_header_email
                ),
            }
            logger.debug(
                "OAuth headers in request",
                extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "oauth_headers": oauth_headers,
                },
            )

        # Process request
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Request-ID"] = request_id

        return response
