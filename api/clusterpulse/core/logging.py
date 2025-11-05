"""Logging configuration for OpenShift Cluster Monitor."""

import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict

from pythonjsonlogger import jsonlogger
from clusterpulse.core.config import settings


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter for structured logging."""

    def add_fields(
        self,
        log_record: Dict[str, Any],
        record: logging.LogRecord,
        message_dict: Dict[str, Any],
    ) -> None:
        """Add custom fields to log record."""
        super().add_fields(log_record, record, message_dict)

        # Add timestamp
        log_record["timestamp"] = datetime.utcnow().isoformat()

        # Add application context
        log_record["app_name"] = settings.app_name
        log_record["app_version"] = settings.app_version
        log_record["environment"] = settings.environment

        # Add standard fields
        log_record["level"] = record.levelname
        log_record["logger"] = record.name

        # Add extra fields if present
        if hasattr(record, "user_id"):
            log_record["user_id"] = record.user_id
        if hasattr(record, "cluster_id"):
            log_record["cluster_id"] = record.cluster_id
        if hasattr(record, "request_id"):
            log_record["request_id"] = record.request_id


def setup_logging() -> None:
    """Configure logging for the application."""
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(settings.log_level.value)

    # Remove existing handlers
    for handler in root_logger.handlers:
        root_logger.removeHandler(handler)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(settings.log_level.value)

    # Set formatter based on configuration
    if settings.log_json:
        formatter = CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
    else:
        formatter = logging.Formatter(settings.log_format)

    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Set log levels for third-party libraries
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("fastapi").setLevel(logging.INFO)
    logging.getLogger("kubernetes").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    # Log startup message
    logger = get_logger(__name__)
    logger.info(
        "Logging configured",
        extra={
            "log_level": settings.log_level.value,
            "log_json": settings.log_json,
        },
    )


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name."""
    return logging.getLogger(name)


class LoggerAdapter(logging.LoggerAdapter):
    """Logger adapter for adding context to log messages."""

    def process(self, msg: str, kwargs: Dict[str, Any]) -> tuple:
        """Process log message and add context."""
        # Add any context from extra
        if "extra" in kwargs:
            extra = kwargs["extra"]
            # Add user context if available
            if "user" in extra:
                extra["user_id"] = extra["user"].get("id", "unknown")
            # Add request context if available
            if "request_id" in extra:
                kwargs["extra"]["request_id"] = extra["request_id"]

        return msg, kwargs


def get_logger_with_context(name: str, **context) -> LoggerAdapter:
    """Get a logger with additional context."""
    logger = get_logger(name)
    return LoggerAdapter(logger, context)


# Convenience function for structured logging
def log_event(logger: logging.Logger, level: str, event: str, **kwargs) -> None:
    """Log a structured event."""
    extra = {"event": event, **kwargs}

    message = f"{event}: {json.dumps(kwargs, default=str)}" if kwargs else event

    if level == "debug":
        logger.debug(message, extra=extra)
    elif level == "info":
        logger.info(message, extra=extra)
    elif level == "warning":
        logger.warning(message, extra=extra)
    elif level == "error":
        logger.error(message, extra=extra)
    elif level == "critical":
        logger.critical(message, extra=extra)
