"""API routes package."""

from . import auth, clusters, custom_resources, health, public, registries

__all__ = ["health", "auth", "clusters", "registries", "public", "custom_resources"]
