"""Integration tests for authentication routes."""

import pytest
from fastapi import status


@pytest.mark.integration
class TestAuthStatusEndpoint:
    """Test GET /api/v1/auth/status endpoint."""

    def test_auth_status_authenticated(self, authenticated_client):
        """Test authentication status for authenticated user."""

        def mock_resolve_groups(username, email=None):
            return ["developers", "cluster-viewers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/status")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["authenticated"] is True
        assert data["user"] is not None
        assert data["user"]["username"] == "john.doe"

    def test_auth_status_unauthenticated(self, test_client):
        """Test authentication status for unauthenticated user."""
        # Remove any auth headers
        test_client.headers.clear()

        response = test_client.get("/api/v1/auth/status")

        # In development mode, may still return authenticated with dev user
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.integration
class TestAuthMeEndpoint:
    """Test GET /api/v1/auth/me endpoint."""

    def test_get_current_user(self, authenticated_client):
        """Test getting current user information."""

        def mock_resolve_groups(username, email=None):
            return ["developers", "cluster-viewers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/me")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["username"] == "john.doe"
        assert data["email"] == "john.doe@example.com"
        assert "groups" in data
        assert len(data["groups"]) > 0

    def test_get_current_user_with_groups(self, authenticated_client):
        """Test that groups are resolved."""

        def mock_resolve_groups(username, email=None):
            return ["developers", "platform-team", "cluster-viewers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/me")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["groups"]) == 3
        assert "developers" in data["groups"]
        assert "platform-team" in data["groups"]
        assert "cluster-viewers" in data["groups"]


@pytest.mark.integration
class TestAuthPermissionsEndpoint:
    """Test GET /api/v1/auth/permissions endpoint."""

    def test_get_permissions_with_access(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_cluster,
        populate_redis_with_policies,
        basic_dev_policy,
        sample_cluster_spec,
        sample_cluster_status,
        sample_cluster_metrics,
    ):
        """Test getting user permissions."""
        populate_redis_with_policies([basic_dev_policy])
        populate_redis_with_cluster(
            "dev-cluster-1",
            sample_cluster_spec,
            sample_cluster_status,
            sample_cluster_metrics,
        )

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/permissions")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "user" in data
        assert "summary" in data
        assert "clusters" in data
        assert "accessible_cluster_names" in data

        # Should have access to dev-cluster-1
        assert "dev-cluster-1" in data["accessible_cluster_names"]

    def test_get_permissions_no_access(self, authenticated_client, fake_redis):
        """Test getting permissions for user with no access."""
        # No policies set up

        def mock_resolve_groups(username, email=None):
            return []

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/permissions")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["summary"]["total_clusters"] == 0
        assert data["accessible_cluster_names"] == []


@pytest.mark.integration
class TestAuthPoliciesEndpoint:
    """Test GET /api/v1/auth/policies endpoint."""

    def test_get_applied_policies(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_policies,
        basic_dev_policy,
    ):
        """Test getting policies applied to user."""
        populate_redis_with_policies([basic_dev_policy])

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/policies")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "user" in data
        assert "total_policies" in data
        assert "policies" in data

        # Should have the dev policy
        assert data["total_policies"] >= 1
        policy_names = [p["policy"]["policy_name"] for p in data["policies"]]
        assert "developers-policy" in policy_names

    def test_get_policies_multiple_groups(
        self,
        authenticated_client,
        fake_redis,
        populate_redis_with_policies,
        basic_dev_policy,
        readonly_policy,
    ):
        """Test getting policies from multiple groups."""
        populate_redis_with_policies([basic_dev_policy, readonly_policy])

        def mock_resolve_groups(username, email=None):
            return ["developers", "cluster-viewers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/policies")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Should have policies from both groups
        assert data["total_policies"] >= 2
        policy_names = [p["policy"]["policy_name"] for p in data["policies"]]
        assert "developers-policy" in policy_names
        assert "readonly-policy" in policy_names


@pytest.mark.integration
class TestAuthCacheClearEndpoint:
    """Test POST /api/v1/auth/cache/clear endpoint."""

    def test_clear_cache(self, authenticated_client, fake_redis):
        """Test clearing user's RBAC cache."""

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.post("/api/v1/auth/cache/clear")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "message" in data
        assert "Cache cleared" in data["message"]
        assert "user" in data


@pytest.mark.integration
class TestAuthLogoutEndpoint:
    """Test POST /api/v1/auth/logout endpoint."""

    def test_logout(self, authenticated_client):
        """Test logout endpoint."""

        def mock_resolve_groups(username, email=None):
            return ["developers"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.post("/api/v1/auth/logout")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "message" in data
        assert "Logout successful" in data["message"]


@pytest.mark.integration
class TestGroupResolution:
    """Test real-time group resolution from Kubernetes."""

    def test_group_resolution_success(self, authenticated_client):
        """Test successful group resolution."""

        def mock_resolve_groups(username, email=None):
            # Simulate successful group lookup
            return ["developers", "platform-team", "sre"]

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/me")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data["groups"]) == 3
        assert set(data["groups"]) == {"developers", "platform-team", "sre"}

    def test_group_resolution_empty(self, authenticated_client):
        """Test user with no groups."""

        def mock_resolve_groups(username, email=None):
            return []

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/me")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["groups"] == []

    def test_group_resolution_by_email(self, authenticated_client):
        """Test group resolution using email identifier."""

        def mock_resolve_groups(username, email=None):
            # Simulate that email is used for group lookup
            if email == "john.doe@example.com":
                return ["developers", "email-verified-users"]
            return []

        import clusterpulse.api.dependencies.auth as auth_module

        auth_module.resolve_groups_realtime = mock_resolve_groups

        response = authenticated_client.get("/api/v1/auth/me")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "email-verified-users" in data["groups"]
