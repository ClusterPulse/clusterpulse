"""Authentication models for OpenShift Cluster Monitor with RBAC support."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, validator


class User(BaseModel):
    """User model extracted from OAuth proxy headers with RBAC support."""

    username: str = Field(..., description="User's username")
    email: Optional[str] = Field(None, description="User's email address or identifier")
    groups: List[str] = Field(default_factory=list, description="User's groups")
    preferred_username: Optional[str] = Field(
        None, description="User's preferred display name"
    )

    # Additional metadata
    authenticated_at: datetime = Field(default_factory=datetime.utcnow)
    auth_provider: str = Field("oauth-proxy", description="Authentication provider")

    @validator("email")
    def validate_email(cls, v):
        """
        Validate email but allow Kubernetes-style identifiers.
        Accept both real emails and Kubernetes identifiers like user@cluster.local
        """
        if v is None:
            return v

        # Allow common Kubernetes/OpenShift patterns
        if any(
            v.endswith(suffix)
            for suffix in [".local", ".svc", ".internal", ".cluster.local"]
        ):
            return v  # These are valid in K8s context

        # For other cases, just do basic validation
        if "@" in v:
            # Basic check - has @ and something on both sides
            parts = v.split("@")
            if len(parts) == 2 and parts[0] and parts[1]:
                return v

        # If no @, it might just be a username, which is also OK
        return v

    @property
    def id(self) -> str:
        """Get user ID (username)."""
        return self.username

    @property
    def display_name(self) -> str:
        """Get display name for the user."""
        return self.preferred_username or self.username

    def has_group(self, group: str) -> bool:
        """Check if user belongs to a specific group."""
        return group in self.groups

    def has_any_group(self, groups: List[str]) -> bool:
        """Check if user belongs to any of the specified groups."""
        return any(group in self.groups for group in groups)

    def has_all_groups(self, groups: List[str]) -> bool:
        """Check if user belongs to all specified groups."""
        return all(group in self.groups for group in groups)

    @property
    def is_valid_email(self) -> bool:
        """Check if the email field contains a valid email address."""
        if not self.email:
            return False

        # Check if it's a Kubernetes-style identifier
        if any(
            self.email.endswith(suffix)
            for suffix in [".local", ".svc", ".internal", ".cluster.local"]
        ):
            return False  # It's a K8s identifier, not a real email

        # Basic email validation
        try:
            from email_validator import validate_email

            validate_email(self.email)
            return True
        except:
            return False

    class Config:
        """Pydantic config."""

        schema_extra = {
            "example": {
                "username": "jdoe",
                "email": "jdoe@example.com",
                "groups": ["developers", "cluster-viewers"],
                "preferred_username": "John Doe",
                "authenticated_at": "2024-01-15T10:30:00Z",
                "auth_provider": "oauth-proxy",
            }
        }


class AuthStatus(BaseModel):
    """Authentication status response."""

    authenticated: bool = Field(..., description="Whether the user is authenticated")
    user: Optional[User] = Field(None, description="Authenticated user details")
    message: Optional[str] = Field(None, description="Additional status message")

    class Config:
        """Pydantic config."""

        schema_extra = {
            "example": {
                "authenticated": True,
                "user": {
                    "username": "jdoe",
                    "email": "jdoe@example.com",
                    "groups": ["developers", "cluster-viewers"],
                    "preferred_username": "John Doe",
                    "authenticated_at": "2024-01-15T10:30:00Z",
                    "auth_provider": "oauth-proxy",
                },
                "message": "Successfully authenticated",
            }
        }
