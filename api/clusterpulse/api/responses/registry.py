"""Response builders for registry endpoints."""

from typing import Any, Dict, Optional


class RegistryStatusBuilder:
    """Builder for registry status responses."""

    def __init__(self, registry_name: str):
        self.data = {
            "name": registry_name,
            "display_name": registry_name,  # Default to name
            "endpoint": None,
            "available": False,
            "error": None,
        }

    def with_spec(self, spec: Optional[Dict]) -> "RegistryStatusBuilder":
        """Add spec data (display name, endpoint)."""
        if spec:
            self.data["display_name"] = spec.get(
                "display_name", self.data["display_name"]
            )
            self.data["endpoint"] = spec.get("endpoint")
        return self

    def with_status(self, status: Optional[Dict]) -> "RegistryStatusBuilder":
        """Add status data (availability, error, response time)."""
        if status:
            self.data["available"] = status.get("available", False)
            if not self.data["available"] and "error" in status:
                self.data["error"] = status["error"]

            # Optionally include response time
            if "response_time" in status:
                self.data["response_time"] = status["response_time"]
        else:
            self.data["error"] = "Registry not found"

        return self

    def with_response_time(
        self, status: Optional[Dict], include: bool
    ) -> "RegistryStatusBuilder":
        """Conditionally include response time."""
        if include and status:
            self.data["response_time"] = status.get("response_time")
        return self

    def build(self) -> Dict[str, Any]:
        """Build and return the final registry status."""
        return self.data
