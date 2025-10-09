"""Configuration management for OpenShift Cluster Monitor with RBAC."""

from enum import Enum
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Environment(str, Enum):
    """Application environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(str, Enum):
    """Logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """Application settings with RBAC configuration."""

    # Application
    app_name: str = "OpenShift Cluster Monitor"
    app_version: str = "0.1.0"
    environment: Environment = Field(Environment.DEVELOPMENT, env="ENVIRONMENT")
    debug: bool = Field(False, env="DEBUG")

    # API Configuration
    api_prefix: str = "/api/v1"
    allowed_origins: List[str] = Field(["*"], env="ALLOWED_ORIGINS")

    # OAuth Proxy Configuration
    oauth_proxy_enabled: bool = Field(True, env="OAUTH_PROXY_ENABLED")
    oauth_header_user: str = Field("X-Forwarded-User", env="OAUTH_HEADER_USER")
    oauth_header_email: str = Field("X-Forwarded-Email", env="OAUTH_HEADER_EMAIL")

    # RBAC Configuration
    rbac_enabled: bool = Field(True, env="RBAC_ENABLED")
    rbac_default_deny: bool = Field(True, env="RBAC_DEFAULT_DENY")
    rbac_cache_ttl: int = Field(300, env="RBAC_CACHE_TTL")  # 5 minutes
    rbac_audit_enabled: bool = Field(True, env="RBAC_AUDIT_ENABLED")
    rbac_group_sync_interval: int = Field(300, env="RBAC_GROUP_SYNC_INTERVAL")

    # Anonymous Access Configuration
    allow_anonymous_access: bool = Field(False, env="ALLOW_ANONYMOUS_ACCESS")
    anonymous_cluster_view: bool = Field(
        False, env="ANONYMOUS_CLUSTER_VIEW"
    )  # View cluster names/health
    public_api_prefix: str = "/api/v1/public"

    # Redis Configuration
    redis_host: str = Field("redis", env="REDIS_HOST")
    redis_port: int = Field(6379, env="REDIS_PORT")
    redis_password: Optional[str] = Field(None, env="REDIS_PASSWORD")
    redis_db: int = Field(0, env="REDIS_DB")
    redis_url: Optional[str] = Field(None, env="REDIS_URL")

    # Security
    session_expire_minutes: int = Field(1440, env="SESSION_EXPIRE_MINUTES")  # 24 hours

    # Logging
    log_level: LogLevel = Field(LogLevel.INFO, env="LOG_LEVEL")
    log_format: str = Field(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s", env="LOG_FORMAT"
    )
    log_json: bool = Field(False, env="LOG_JSON")

    # Server
    host: str = Field("0.0.0.0", env="HOST")
    port: int = Field(8080, env="PORT")
    workers: int = Field(1, env="WORKERS")
    reload: bool = Field(False, env="RELOAD")

    # Health Check
    health_check_path: str = "/health"
    readiness_check_path: str = "/ready"

    # Policy Controller Settings
    policy_controller_enabled: bool = Field(True, env="POLICY_CONTROLLER_ENABLED")
    policy_cache_ttl: int = Field(300, env="POLICY_CACHE_TTL")
    group_cache_ttl: int = Field(300, env="GROUP_CACHE_TTL")
    max_policies_per_user: int = Field(100, env="MAX_POLICIES_PER_USER")

    @validator("redis_url", pre=True)
    def build_redis_url(cls, v, values):
        """Build Redis URL from components if not provided."""
        if v:
            return v

        host = values.get("redis_host", "redis")
        port = values.get("redis_port", 6379)
        password = values.get("redis_password")
        db = values.get("redis_db", 0)

        if password:
            return f"redis://:{password}@{host}:{port}/{db}"
        return f"redis://{host}:{port}/{db}"

    # Trusted hosts
    trusted_hosts: List[str] = Field(
        [
            "*.apps.openshift.com",
            "localhost",
            "127.0.0.1",
        ],
        env="TRUSTED_HOSTS",
    )

    @validator("trusted_hosts", pre=True)
    def parse_trusted_hosts(cls, v):
        """Parse trusted hosts from comma-separated string."""
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v

    @validator("allowed_origins", pre=True)
    def parse_allowed_origins(cls, v):
        """Parse allowed origins from comma-separated string."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    class Config:
        """Pydantic config."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience function for getting settings
settings = get_settings()
