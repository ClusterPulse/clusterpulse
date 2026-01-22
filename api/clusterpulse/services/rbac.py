"""Role-Based Access Control engine for ClusterPulse."""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import redis

logger = logging.getLogger(__name__)


class Action(str, Enum):
    """System actions."""

    VIEW = "view"
    VIEW_METRICS = "view_metrics"
    VIEW_SENSITIVE = "view_sensitive"
    VIEW_COSTS = "view_costs"
    VIEW_SECRETS = "view_secrets"
    VIEW_METADATA = "view_metadata"
    VIEW_AUDIT = "view_audit"
    EDIT = "edit"
    DELETE = "delete"
    EXECUTE = "execute"


class ResourceType(str, Enum):
    """Resource types."""

    CLUSTER = "cluster"
    NODE = "node"
    OPERATOR = "operator"
    NAMESPACE = "namespace"
    POD = "pod"
    ALERT = "alert"
    EVENT = "event"
    METRIC = "metric"
    POLICY = "policy"
    CUSTOM = "custom"


class Decision(str, Enum):
    """Authorization decisions."""

    ALLOW = "allow"
    DENY = "deny"
    PARTIAL = "partial"


class Visibility(str, Enum):
    """Resource visibility."""

    ALL = "all"
    NONE = "none"
    FILTERED = "filtered"


@dataclass
class Principal:
    """Entity making the request."""

    username: str
    email: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    is_service_account: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.username

    @property
    def cache_key(self) -> str:
        groups_hash = ",".join(sorted(self.groups))
        return f"{self.username}:{groups_hash}"


@dataclass
class Resource:
    """Resource being accessed."""

    type: ResourceType
    name: str
    namespace: Optional[str] = None
    cluster: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        parts = [self.type.value]
        if self.cluster:
            parts.append(self.cluster)
        if self.namespace:
            parts.append(self.namespace)
        parts.append(self.name)
        return ":".join(parts)


@dataclass
class Request:
    """Authorization request."""

    principal: Principal
    action: Action
    resource: Resource
    context: Dict[str, Any] = field(default_factory=dict)

    @property
    def cache_key(self) -> str:
        return f"{self.principal.cache_key}:{self.action.value}:{self.resource.id}"


@dataclass
class Filter:
    """Resource filter configuration."""

    visibility: Visibility = Visibility.ALL
    include: Set[str] = field(default_factory=set)
    exclude: Set[str] = field(default_factory=set)
    patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches(self, item: str, labels: Dict[str, str] = None) -> bool:
        """Check if item matches filter criteria."""
        if self.visibility == Visibility.NONE:
            return False
        if self.visibility == Visibility.ALL and not self.exclude and not self.include:
            return True

        if item in self.exclude:
            return False

        if self.include:
            if item not in self.include:
                matched = any(pattern.match(item) for _, pattern in self.patterns)
                if not matched:
                    return False

        if self.labels and labels:
            for key, value in self.labels.items():
                if labels.get(key) != value:
                    return False

        return True

    def is_empty(self) -> bool:
        """Check if filter has no restrictions."""
        return (
            self.visibility == Visibility.ALL
            and not self.include
            and not self.exclude
            and not self.patterns
            and not self.labels
        )


@dataclass
class RBACDecision:
    """Authorization decision result."""

    decision: Decision
    request: Request
    reason: str = ""
    filters: Dict[ResourceType, Filter] = field(default_factory=dict)
    permissions: Set[Action] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    applied_policies: List[str] = field(default_factory=list)
    cached: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.PARTIAL)

    @property
    def denied(self) -> bool:
        return self.decision == Decision.DENY

    def can(self, action: Action) -> bool:
        return action in self.permissions

    def get_filter(self, resource_type: ResourceType) -> Optional[Filter]:
        return self.filters.get(resource_type)


# =============================================================================
# Custom Resource Authorization Data Classes
# =============================================================================


@dataclass
class CustomResourceFilter:
    """Filter configuration for custom resources.

    Supports namespace, name, and arbitrary field-based filtering with
    both literal matches and compiled regex patterns.
    """

    visibility: Visibility = Visibility.ALL

    # Namespace filtering
    namespace_literals: Set[str] = field(default_factory=set)
    namespace_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    namespace_exclude_literals: Set[str] = field(default_factory=set)
    namespace_exclude_patterns: List[Tuple[str, re.Pattern]] = field(
        default_factory=list
    )

    # Name filtering
    name_literals: Set[str] = field(default_factory=set)
    name_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    name_exclude_literals: Set[str] = field(default_factory=set)
    name_exclude_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)

    # Field-based filtering: field_name -> (allowed_values, allowed_patterns, denied_values, denied_patterns)
    field_filters: Dict[
        str,
        Tuple[
            Set[str],
            List[Tuple[str, re.Pattern]],
            Set[str],
            List[Tuple[str, re.Pattern]],
        ],
    ] = field(default_factory=dict)

    def matches_namespace(self, namespace: Optional[str]) -> bool:
        """Check if namespace passes filter criteria."""
        if self.visibility == Visibility.NONE:
            return False

        if namespace is None:
            # Cluster-scoped resources pass namespace filter
            return True

        # Check exclusions first
        if namespace in self.namespace_exclude_literals:
            return False
        for _, pattern in self.namespace_exclude_patterns:
            if pattern.match(namespace):
                return False

        # If no include filters, allow all non-excluded
        if not self.namespace_literals and not self.namespace_patterns:
            return True

        # Check inclusions
        if namespace in self.namespace_literals:
            return True
        for _, pattern in self.namespace_patterns:
            if pattern.match(namespace):
                return True

        return False

    def matches_name(self, name: str) -> bool:
        """Check if resource name passes filter criteria."""
        if self.visibility == Visibility.NONE:
            return False

        # Check exclusions first
        if name in self.name_exclude_literals:
            return False
        for _, pattern in self.name_exclude_patterns:
            if pattern.match(name):
                return False

        # If no include filters, allow all non-excluded
        if not self.name_literals and not self.name_patterns:
            return True

        # Check inclusions
        if name in self.name_literals:
            return True
        for _, pattern in self.name_patterns:
            if pattern.match(name):
                return True

        return False

    def matches_field(self, field_name: str, field_value: Any) -> bool:
        """Check if field value passes filter criteria."""
        if field_name not in self.field_filters:
            return True

        allowed_literals, allowed_patterns, denied_literals, denied_patterns = (
            self.field_filters[field_name]
        )
        value_str = str(field_value) if field_value is not None else ""

        # Check exclusions first
        if value_str in denied_literals:
            return False
        for _, pattern in denied_patterns:
            if pattern.match(value_str):
                return False

        # If no include filters, allow all non-excluded
        if not allowed_literals and not allowed_patterns:
            return True

        # Check inclusions
        if value_str in allowed_literals:
            return True
        for _, pattern in allowed_patterns:
            if pattern.match(value_str):
                return True

        return False

    def is_unrestricted(self) -> bool:
        """Check if filter imposes no restrictions."""
        return (
            self.visibility == Visibility.ALL
            and not self.namespace_literals
            and not self.namespace_patterns
            and not self.namespace_exclude_literals
            and not self.namespace_exclude_patterns
            and not self.name_literals
            and not self.name_patterns
            and not self.name_exclude_literals
            and not self.name_exclude_patterns
            and not self.field_filters
        )


@dataclass
class CustomResourceDecision:
    """Authorization decision for custom resource access.

    Contains the decision, applicable filters, and aggregation visibility controls.
    """

    decision: Decision
    resource_type_name: str
    cluster: Optional[str] = None
    reason: str = ""
    filters: CustomResourceFilter = field(default_factory=CustomResourceFilter)
    allowed_aggregations: Optional[Set[str]] = None  # None means all allowed
    denied_aggregations: Set[str] = field(default_factory=set)
    permissions: Set[Action] = field(default_factory=set)
    applied_policies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    cached: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.PARTIAL)

    @property
    def denied(self) -> bool:
        return self.decision == Decision.DENY

    def can(self, action: Action) -> bool:
        return action in self.permissions

    def is_aggregation_allowed(self, aggregation_name: str) -> bool:
        """Check if a specific aggregation is visible to the user."""
        if aggregation_name in self.denied_aggregations:
            return False
        if self.allowed_aggregations is not None:
            return aggregation_name in self.allowed_aggregations
        return True


# =============================================================================
# RBAC Engine
# =============================================================================


class RBACEngine:
    """RBAC authorization engine supporting built-in and custom resources."""

    def __init__(self, redis_client: redis.Redis, cache_ttl: int = 0):
        self.redis = redis_client
        self.cache_ttl = cache_ttl
        self._policy_cache = {}
        self._cache_hits = 0
        self._cache_misses = 0
        self._caching_enabled = cache_ttl > 0

    # =========================================================================
    # Standard Resource Authorization
    # =========================================================================

    def authorize(self, request: Request) -> RBACDecision:
        """Authorize a request for standard resources."""
        if self._caching_enabled:
            cache_key = f"rbac:decision:{request.cache_key}"
            cached = self._get_cached_decision(cache_key)
            if cached:
                self._cache_hits += 1
                cached.cached = True
                return cached

        self._cache_misses += 1

        policies = self._get_applicable_policies(request.principal)
        decision = self._evaluate_policies(request, policies)

        if self._caching_enabled and self.cache_ttl > 0:
            self._cache_decision(cache_key, decision)

        if decision.metadata.get("audit_required"):
            self._audit_log(request, decision)

        return decision

    def filter_resources(
        self,
        principal: Principal,
        resources: List[Dict[str, Any]],
        resource_type: ResourceType,
        cluster: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Filter resources based on permissions."""
        if not resources:
            return []

        dummy_resource = Resource(type=resource_type, name="*", cluster=cluster)
        request = Request(
            principal=principal, action=Action.VIEW, resource=dummy_resource
        )

        decision = self.authorize(request)

        if decision.denied:
            return []

        primary_filter = decision.get_filter(resource_type)

        if primary_filter and primary_filter.visibility == Visibility.NONE:
            return []

        if decision.decision == Decision.ALLOW and (
            not primary_filter
            or (
                primary_filter.visibility == Visibility.ALL
                and primary_filter.is_empty()
            )
        ):
            return resources

        namespace_filter = decision.get_filter(ResourceType.NAMESPACE)

        filtered = []
        for resource in resources:
            if not self._should_show_resource(
                resource, resource_type, primary_filter, namespace_filter
            ):
                continue

            filtered_resource = self._apply_data_filters(
                resource, resource_type, decision.permissions
            )
            filtered.append(filtered_resource)

        return filtered

    def get_accessible_clusters(self, principal: Principal) -> List[str]:
        """Get clusters accessible to principal."""
        all_clusters = self.redis.smembers("clusters:all")
        accessible = []

        for cluster_name in all_clusters:
            resource = Resource(
                type=ResourceType.CLUSTER, name=cluster_name, cluster=cluster_name
            )
            request = Request(
                principal=principal, action=Action.VIEW, resource=resource
            )

            if self.authorize(request).allowed:
                accessible.append(cluster_name)

        return sorted(accessible)

    def get_permissions(self, principal: Principal, resource: Resource) -> Set[Action]:
        """Get all permissions for principal on resource."""
        permissions = set()

        for action in Action:
            request = Request(principal=principal, action=action, resource=resource)
            if self.authorize(request).allowed:
                permissions.add(action)

        return permissions

    # =========================================================================
    # Custom Resource Authorization
    # =========================================================================

    def authorize_custom_resource(
        self,
        principal: Principal,
        resource_type_name: str,
        cluster: Optional[str] = None,
        action: Action = Action.VIEW,
    ) -> CustomResourceDecision:
        """Authorize access to a custom resource type.

        Args:
            principal: The user/service making the request
            resource_type_name: The resourceTypeName from MetricSource (e.g., "pvc")
            cluster: Optional cluster name (None for all clusters)
            action: The action being performed

        Returns:
            CustomResourceDecision with authorization result and applicable filters
        """
        # Check cache if enabled
        if self._caching_enabled:
            cache_key = self._custom_resource_cache_key(
                principal, resource_type_name, cluster, action
            )
            cached = self._get_cached_custom_decision(cache_key)
            if cached:
                self._cache_hits += 1
                cached.cached = True
                return cached

        self._cache_misses += 1

        # If cluster is specified, first verify cluster access
        if cluster:
            cluster_resource = Resource(
                type=ResourceType.CLUSTER, name=cluster, cluster=cluster
            )
            cluster_request = Request(
                principal=principal, action=action, resource=cluster_resource
            )
            cluster_decision = self.authorize(cluster_request)

            if cluster_decision.denied:
                decision = CustomResourceDecision(
                    decision=Decision.DENY,
                    resource_type_name=resource_type_name,
                    cluster=cluster,
                    reason=f"Access denied to cluster '{cluster}'",
                )
                return decision

        # Get applicable policies
        policies = self._get_applicable_policies(principal)

        # Evaluate custom resource rules
        decision = self._evaluate_custom_resource_policies(
            principal, resource_type_name, cluster, action, policies
        )

        # Cache if enabled
        if self._caching_enabled and self.cache_ttl > 0:
            cache_key = self._custom_resource_cache_key(
                principal, resource_type_name, cluster, action
            )
            self._cache_custom_decision(cache_key, decision)

        return decision

    def filter_custom_resources(
        self,
        principal: Principal,
        resources: List[Dict[str, Any]],
        resource_type_name: str,
        cluster: str,
    ) -> List[Dict[str, Any]]:
        """Filter custom resources based on RBAC permissions.
    
        Args:
            principal: The user/service making the request
            resources: List of resource dictionaries to filter
            resource_type_name: The resourceTypeName from MetricSource
            cluster: The cluster name
    
        Returns:
            Filtered list of resources the user can access
        """
        if not resources:
            return []
    
        decision = self.authorize_custom_resource(
            principal, resource_type_name, cluster, Action.VIEW
        )
    
        if decision.denied:
            logger.debug(
                f"Custom resource access denied for {principal.username} "
                f"on {resource_type_name}: {decision.reason}"
            )
            return []
    
        if decision.decision == Decision.ALLOW and decision.filters.is_unrestricted():
            return resources
    
        filtered = []
        for resource in resources:
            if self._custom_resource_matches_filters(resource, decision.filters):
                filtered.append(resource)
    
        logger.debug(
            f"Filtered {len(resources)} -> {len(filtered)} custom resources "
            f"for {principal.username} on {resource_type_name}"
        )
    
        return filtered

    def get_accessible_custom_resource_types(self, principal: Principal) -> List[str]:
        """Get all custom resource types the principal can access.

        This implements implicit deny - only types explicitly granted
        in a policy are returned.

        Args:
            principal: The user/service making the request

        Returns:
            Sorted list of accessible resource type names
        """
        policies = self._get_applicable_policies(principal)
        accessible_types = set()
    
        for policy in policies:
            if not self._is_policy_valid(policy):
                continue
    
            if policy.get("effect") != "Allow":
                continue
    
            # Check cluster_rules for custom_resources
            for rule in policy.get("cluster_rules", []):
                custom_resources = rule.get("custom_resources", {})
                for type_name, config in custom_resources.items():
                    visibility = config.get("visibility", "all")
                    if visibility != "none":
                        accessible_types.add(type_name)
    
        return sorted(accessible_types)

    def filter_aggregations(
        self,
        principal: Principal,
        aggregations: Dict[str, Any],
        resource_type_name: str,
        cluster: str,
    ) -> Dict[str, Any]:
        """Filter aggregations based on RBAC permissions.

        Args:
            principal: The user/service making the request
            aggregations: Dict of aggregation name to value
            resource_type_name: The resourceTypeName from MetricSource
            cluster: The cluster name

        Returns:
            Filtered aggregations dict
        """
        if not aggregations:
            return {}

        decision = self.authorize_custom_resource(
            principal, resource_type_name, cluster, Action.VIEW_METRICS
        )

        if decision.denied:
            return {}

        # Apply aggregation visibility filters
        filtered = {}
        for name, value in aggregations.items():
            if decision.is_aggregation_allowed(name):
                filtered[name] = value

        return filtered

    def clear_custom_resource_cache(
        self,
        principal: Optional[Principal] = None,
        resource_type_name: Optional[str] = None,
    ) -> int:
        """Clear custom resource authorization cache.

        Args:
            principal: If provided, only clear cache for this principal
            resource_type_name: If provided, only clear cache for this type

        Returns:
            Number of cache entries cleared
        """
        if not self._caching_enabled:
            return 0

        pattern_parts = ["rbac:custom"]
        if principal:
            pattern_parts.append(principal.cache_key)
        else:
            pattern_parts.append("*")

        if resource_type_name:
            pattern_parts.append(resource_type_name)
        else:
            pattern_parts.append("*")

        pattern_parts.append("*")  # cluster
        pattern_parts.append("*")  # action

        pattern = ":".join(pattern_parts)

        cursor = 0
        count = 0
        while True:
            cursor, keys = self.redis.scan(cursor, match=pattern, count=100)
            if keys:
                self.redis.delete(*keys)
                count += len(keys)
            if cursor == 0:
                break

        return count

    # =========================================================================
    # Custom Resource Policy Evaluation
    # =========================================================================
    def _evaluate_custom_resource_policies(
        self,
        principal: Principal,
        resource_type_name: str,
        cluster: Optional[str],
        action: Action,
        policies: List[Dict],
    ) -> CustomResourceDecision:
        """Evaluate policies for custom resource authorization."""
        decision = CustomResourceDecision(
            decision=Decision.DENY,
            resource_type_name=resource_type_name,
            cluster=cluster,
            reason=f"No policy grants access to custom resource type: {resource_type_name}",
        )
    
        for policy in policies:
            if not self._is_policy_valid(policy):
                continue
    
            if policy.get("effect") == "Deny":
                # Check if this deny policy affects this resource type
                for rule in policy.get("cluster_rules", []):
                    if resource_type_name in rule.get("custom_resources", {}):
                        decision.decision = Decision.DENY
                        decision.reason = f"Denied by policy {policy.get('policy_name', 'unknown')}"
                        decision.applied_policies.append(
                            policy.get("_key", policy.get("policy_name", "unknown"))
                        )
                        return decision
                continue
    
            if policy.get("effect") != "Allow":
                continue
    
            # Search through cluster_rules for custom_resources
            for rule in policy.get("cluster_rules", []):
                custom_resources = rule.get("custom_resources", {})
                if resource_type_name not in custom_resources:
                    continue
    
                config = custom_resources[resource_type_name]
                decision.applied_policies.append(
                    policy.get("_key", policy.get("policy_name", "unknown"))
                )
    
                visibility = config.get("visibility", "all")
                if visibility == "none":
                    continue
    
                filters = self._parse_custom_resource_filters(config)
    
                if visibility == "all" and filters.is_unrestricted():
                    decision.decision = Decision.ALLOW
                else:
                    decision.decision = Decision.PARTIAL
                    filters.visibility = Visibility.FILTERED
    
                decision.filters = filters
                decision.reason = f"Allowed by policy {policy.get('policy_name', 'unknown')}"
    
                permissions = config.get("permissions", {"view": True})
                decision.permissions = self._extract_custom_permissions(permissions)
    
                agg_config = config.get("aggregation_rules") or {}
                if "include" in agg_config:
                    decision.allowed_aggregations = set(agg_config["include"])
                if "exclude" in agg_config:
                    decision.denied_aggregations = set(agg_config["exclude"])
    
                return decision
    
        return decision

    def _parse_custom_resource_filters(
        self, config: Dict[str, Any]
    ) -> CustomResourceFilter:
        """Parse custom resource filter configuration from policy."""
        result = CustomResourceFilter()
    
        # Handle namespace_filter (your policy structure)
        ns_config = config.get("namespace_filter", {})
        if ns_config:
            result.namespace_literals, result.namespace_patterns = self._parse_filter_specs(
                ns_config.get("allowed_literals", []),
                ns_config.get("allowed_patterns", []),
            )
            (
                result.namespace_exclude_literals,
                result.namespace_exclude_patterns,
            ) = self._parse_filter_specs(
                ns_config.get("denied_literals", []),
                ns_config.get("denied_patterns", []),
            )
    
        # Handle name_filter
        name_config = config.get("name_filter") or {}
        if name_config:
            result.name_literals, result.name_patterns = self._parse_filter_specs(
                name_config.get("allowed_literals", []),
                name_config.get("allowed_patterns", []),
            )
            (
                result.name_exclude_literals,
                result.name_exclude_patterns,
            ) = self._parse_filter_specs(
                name_config.get("denied_literals", []),
                name_config.get("denied_patterns", []),
            )
    
        # Handle field_filters
        field_configs = config.get("field_filters", {})
        for field_name, field_spec in field_configs.items():
            allowed_literals, allowed_patterns = self._parse_filter_specs(
                field_spec.get("allowed_literals", []),
                field_spec.get("allowed_patterns", []),
            )
            denied_literals, denied_patterns = self._parse_filter_specs(
                field_spec.get("denied_literals", []),
                field_spec.get("denied_patterns", []),
            )
            result.field_filters[field_name] = (
                allowed_literals,
                allowed_patterns,
                denied_literals,
                denied_patterns,
            )
    
        if result.is_unrestricted():
            result.visibility = Visibility.ALL
        else:
            result.visibility = Visibility.FILTERED
    
        return result

    def _parse_filter_specs(
        self,
        literals: List[str],
        patterns: List[List[str]],
    ) -> Tuple[Set[str], List[Tuple[str, re.Pattern]]]:
        """Parse literal values and compile pattern specifications."""
        literal_set = set(literals) if literals else set()
        compiled_patterns = []

        for pattern_spec in patterns or []:
            try:
                # Pattern spec is [pattern_str, regex_str]
                if isinstance(pattern_spec, list) and len(pattern_spec) >= 2:
                    pattern_str, regex_str = pattern_spec[0], pattern_spec[1]
                    compiled = re.compile(regex_str)
                    compiled_patterns.append((pattern_str, compiled))
                elif isinstance(pattern_spec, str):
                    # Simple string pattern - treat as literal prefix match
                    compiled = re.compile(f"^{re.escape(pattern_spec)}")
                    compiled_patterns.append((pattern_spec, compiled))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern_spec}': {e}")
                # Fail closed - invalid pattern means no match
                continue

        return literal_set, compiled_patterns

    def _extract_custom_permissions(
        self, permissions_config: Dict[str, bool]
    ) -> Set[Action]:
        """Extract Action set from permissions configuration."""
        permissions = set()
        permission_mapping = {
            "view": Action.VIEW,
            "viewMetrics": Action.VIEW_METRICS,
            "viewSensitive": Action.VIEW_SENSITIVE,
            "viewCosts": Action.VIEW_COSTS,
            "viewSecrets": Action.VIEW_SECRETS,
            "viewMetadata": Action.VIEW_METADATA,
            "viewAuditInfo": Action.VIEW_AUDIT,
        }

        for key, action in permission_mapping.items():
            if permissions_config.get(key):
                permissions.add(action)

        return permissions

    def _custom_resource_matches_filters(
        self,
        resource: Dict[str, Any],
        filters: CustomResourceFilter,
    ) -> bool:
        """Check if a custom resource matches all filter criteria."""
        if filters.visibility == Visibility.NONE:
            return False
    
        namespace = resource.get("_namespace")
        name = resource.get("_name")
        if name is None:
            logger.warning("Resource missing _name field, excluding from results")
            return False
    
        if not filters.matches_namespace(namespace):
            return False
    
        if not filters.matches_name(name):
            return False
    
        # Field filters check the values dict where extracted fields are stored
        values = resource.get("values", {})
        for field_name in filters.field_filters:
            field_value = values.get(field_name)
            if not filters.matches_field(field_name, field_value):
                return False
    
        return True

    def _custom_resource_cache_key(
        self,
        principal: Principal,
        resource_type_name: str,
        cluster: Optional[str],
        action: Action,
    ) -> str:
        """Generate cache key for custom resource decisions."""
        cluster_part = cluster or "all"
        return f"rbac:custom:{principal.cache_key}:{resource_type_name}:{cluster_part}:{action.value}"

    def _get_cached_custom_decision(
        self, cache_key: str
    ) -> Optional[CustomResourceDecision]:
        """Retrieve cached custom resource decision."""
        try:
            cached = self.redis.get(cache_key)
            if not cached:
                return None

            data = json.loads(cached)
            decision = CustomResourceDecision(
                decision=Decision(data["decision"]),
                resource_type_name=data["resource_type_name"],
                cluster=data.get("cluster"),
                reason=data["reason"],
                applied_policies=data.get("applied_policies", []),
                metadata=data.get("metadata", {}),
            )

            # Rebuild permissions
            decision.permissions = set(Action(a) for a in data.get("permissions", []))

            # Rebuild aggregation visibility
            if data.get("allowed_aggregations") is not None:
                decision.allowed_aggregations = set(data["allowed_aggregations"])
            decision.denied_aggregations = set(data.get("denied_aggregations", []))

            # Rebuild filters
            filters_data = data.get("filters", {})
            decision.filters = self._deserialize_custom_filter(filters_data)

            return decision
        except Exception as e:
            logger.debug(f"Custom resource cache retrieval failed: {e}")
            return None

    def _cache_custom_decision(
        self, cache_key: str, decision: CustomResourceDecision
    ) -> None:
        """Cache custom resource authorization decision."""
        try:
            data = {
                "decision": decision.decision.value,
                "resource_type_name": decision.resource_type_name,
                "cluster": decision.cluster,
                "reason": decision.reason,
                "permissions": [a.value for a in decision.permissions],
                "applied_policies": decision.applied_policies,
                "metadata": decision.metadata,
                "allowed_aggregations": (
                    list(decision.allowed_aggregations)
                    if decision.allowed_aggregations is not None
                    else None
                ),
                "denied_aggregations": list(decision.denied_aggregations),
                "filters": self._serialize_custom_filter(decision.filters),
            }

            self.redis.setex(cache_key, self.cache_ttl, json.dumps(data))
        except Exception as e:
            logger.debug(f"Custom resource cache storage failed: {e}")

    def _serialize_custom_filter(self, filters: CustomResourceFilter) -> Dict[str, Any]:
        """Serialize CustomResourceFilter for caching."""
        return {
            "visibility": filters.visibility.value,
            "namespace_literals": list(filters.namespace_literals),
            "namespace_patterns": [
                [p, pat.pattern] for p, pat in filters.namespace_patterns
            ],
            "namespace_exclude_literals": list(filters.namespace_exclude_literals),
            "namespace_exclude_patterns": [
                [p, pat.pattern] for p, pat in filters.namespace_exclude_patterns
            ],
            "name_literals": list(filters.name_literals),
            "name_patterns": [[p, pat.pattern] for p, pat in filters.name_patterns],
            "name_exclude_literals": list(filters.name_exclude_literals),
            "name_exclude_patterns": [
                [p, pat.pattern] for p, pat in filters.name_exclude_patterns
            ],
            "field_filters": {
                field: [
                    list(allowed_lits),
                    [[p, pat.pattern] for p, pat in allowed_pats],
                    list(denied_lits),
                    [[p, pat.pattern] for p, pat in denied_pats],
                ]
                for field, (
                    allowed_lits,
                    allowed_pats,
                    denied_lits,
                    denied_pats,
                ) in filters.field_filters.items()
            },
        }

    def _deserialize_custom_filter(self, data: Dict[str, Any]) -> CustomResourceFilter:
        """Deserialize CustomResourceFilter from cache."""
        filters = CustomResourceFilter()

        try:
            filters.visibility = Visibility(data.get("visibility", "all"))
        except ValueError:
            filters.visibility = Visibility.ALL

        filters.namespace_literals = set(data.get("namespace_literals", []))
        filters.namespace_patterns = self._compile_pattern_list(
            data.get("namespace_patterns", [])
        )
        filters.namespace_exclude_literals = set(
            data.get("namespace_exclude_literals", [])
        )
        filters.namespace_exclude_patterns = self._compile_pattern_list(
            data.get("namespace_exclude_patterns", [])
        )

        filters.name_literals = set(data.get("name_literals", []))
        filters.name_patterns = self._compile_pattern_list(
            data.get("name_patterns", [])
        )
        filters.name_exclude_literals = set(data.get("name_exclude_literals", []))
        filters.name_exclude_patterns = self._compile_pattern_list(
            data.get("name_exclude_patterns", [])
        )

        for field, (
            allowed_lits,
            allowed_pats,
            denied_lits,
            denied_pats,
        ) in data.get("field_filters", {}).items():
            filters.field_filters[field] = (
                set(allowed_lits),
                self._compile_pattern_list(allowed_pats),
                set(denied_lits),
                self._compile_pattern_list(denied_pats),
            )

        return filters

    def _compile_pattern_list(
        self, patterns: List[List[str]]
    ) -> List[Tuple[str, re.Pattern]]:
        """Compile a list of [pattern_str, regex] pairs."""
        compiled = []
        for pattern_spec in patterns:
            if isinstance(pattern_spec, list) and len(pattern_spec) >= 2:
                try:
                    compiled.append((pattern_spec[0], re.compile(pattern_spec[1])))
                except re.error:
                    continue
        return compiled

    # =========================================================================
    # Standard RBAC Methods (unchanged)
    # =========================================================================

    def clear_cache(self, principal: Optional[Principal] = None):
        """Clear authorization cache."""
        if not self._caching_enabled:
            return 0

        pattern = (
            f"rbac:decision:{principal.cache_key}:*" if principal else "rbac:decision:*"
        )

        cursor = 0
        count = 0
        while True:
            cursor, keys = self.redis.scan(cursor, match=pattern, count=100)
            if keys:
                self.redis.delete(*keys)
                count += len(keys)
            if cursor == 0:
                break

        return count

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        total_requests = self._cache_hits + self._cache_misses

        return {
            "caching_enabled": self._caching_enabled,
            "cache_ttl": self.cache_ttl,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "total_requests": total_requests,
            "cache_hit_rate": (
                self._cache_hits / total_requests if total_requests > 0 else 0
            ),
            "security_mode": "real-time" if not self._caching_enabled else "cached",
        }

    def _should_show_resource(
        self,
        resource: Dict[str, Any],
        resource_type: ResourceType,
        primary_filter: Optional[Filter],
        namespace_filter: Optional[Filter],
    ) -> bool:
        """Determine if resource should be shown."""
        if primary_filter:
            if primary_filter.visibility == Visibility.NONE:
                return False
            elif (
                primary_filter.visibility == Visibility.ALL
                and primary_filter.is_empty()
            ):
                if resource_type in [
                    ResourceType.POD,
                    ResourceType.OPERATOR,
                    ResourceType.EVENT,
                ]:
                    if namespace_filter:
                        return self._check_namespace_filter(
                            resource, resource_type, namespace_filter
                        )
                return True

        name = self._extract_resource_name(resource, resource_type)
        labels = resource.get("labels", {})

        if resource_type in [
            ResourceType.POD,
            ResourceType.OPERATOR,
            ResourceType.EVENT,
        ]:
            if namespace_filter and namespace_filter.visibility == Visibility.NONE:
                return False
            if namespace_filter and not self._check_namespace_filter(
                resource, resource_type, namespace_filter
            ):
                return False

        if primary_filter:
            if resource_type == ResourceType.OPERATOR:
                return self._should_show_operator(
                    resource, primary_filter, namespace_filter
                )
            if not primary_filter.matches(name, labels):
                return False

        return True

    def _check_namespace_filter(
        self,
        resource: Dict[str, Any],
        resource_type: ResourceType,
        namespace_filter: Filter,
    ) -> bool:
        """Check namespace filter."""
        if namespace_filter.visibility == Visibility.NONE:
            return False

        if (
            namespace_filter.visibility == Visibility.ALL
            and namespace_filter.is_empty()
        ):
            return True

        if resource_type == ResourceType.OPERATOR:
            available_ns = resource.get("available_in_namespaces", [])
            if available_ns == ["*"]:
                return namespace_filter.visibility != Visibility.NONE
            return any(namespace_filter.matches(ns) for ns in available_ns)
        else:
            namespace = resource.get("namespace", "")
            return namespace_filter.matches(namespace) if namespace else True

    def _should_show_operator(
        self,
        operator: Dict[str, Any],
        operator_filter: Filter,
        namespace_filter: Optional[Filter],
    ) -> bool:
        """Check operator visibility."""
        if operator_filter.visibility == Visibility.NONE:
            return False

        if operator_filter.visibility == Visibility.ALL and operator_filter.is_empty():
            if namespace_filter:
                return self._check_namespace_filter(
                    operator, ResourceType.OPERATOR, namespace_filter
                )
            return True

        operator_name = operator.get("name", "")
        display_name = operator.get("display_name", "")

        name_key = f"name:{operator_name}"
        display_name_key = f"name:{display_name}"

        if any(
            key in operator_filter.exclude
            for key in [operator_name, name_key, display_name_key]
        ):
            return False

        if operator_filter.include:
            name_matched = any(
                key in operator_filter.include
                for key in [operator_name, name_key, display_name_key]
            )

            if not name_matched:
                for pattern_str, pattern in operator_filter.patterns:
                    if pattern_str.startswith("name:"):
                        if pattern.match(operator_name) or pattern.match(display_name):
                            name_matched = True
                            break

                if not name_matched:
                    return False

        if namespace_filter and namespace_filter.visibility != Visibility.ALL:
            available_namespaces = operator.get("available_in_namespaces", [])
            if available_namespaces == ["*"]:
                return namespace_filter.visibility != Visibility.NONE

            for ns in available_namespaces:
                if namespace_filter.matches(ns):
                    ns_key = f"ns:{ns}"
                    if ns_key not in operator_filter.exclude:
                        return True
            return False

        return True

    def _get_applicable_policies(self, principal: Principal) -> List[Dict[str, Any]]:
        """Get policies applicable to principal."""
        policy_keys = set()

        user_policies = self.redis.zrevrange(
            f"policy:user:{principal.username}:sorted", 0, -1, withscores=True
        )
        for policy_key, priority in user_policies:
            policy_keys.add((policy_key, int(priority)))

        for group in principal.groups:
            group_policies = self.redis.zrevrange(
                f"policy:group:{group}:sorted", 0, -1, withscores=True
            )
            for policy_key, priority in group_policies:
                policy_keys.add((policy_key, int(priority)))

        if principal.is_service_account:
            sa_policies = self.redis.zrevrange(
                f"policy:sa:{principal.username}:sorted", 0, -1, withscores=True
            )
            for policy_key, priority in sa_policies:
                policy_keys.add((policy_key, int(priority)))

        sorted_keys = sorted(policy_keys, key=lambda x: x[1], reverse=True)

        policies = []
        for policy_key, _ in sorted_keys:
            policy_data = self.redis.hget(policy_key, "data")
            if policy_data:
                policy = json.loads(policy_data)
                policy["_key"] = policy_key
                policies.append(policy)

        return policies

    def _evaluate_policies(
        self, request: Request, policies: List[Dict]
    ) -> RBACDecision:
        """Evaluate policies for authorization."""
        decision = RBACDecision(
            decision=Decision.DENY, request=request, reason="No matching policies found"
        )

        for policy in policies:
            if not self._is_policy_valid(policy):
                continue

            match = self._match_resource(request.resource, policy)
            if not match:
                continue

            decision.applied_policies.append(policy["_key"])

            if policy["effect"] == "Deny":
                decision.decision = Decision.DENY
                decision.reason = f"Denied by policy {policy['policy_name']}"
                break
            elif policy["effect"] == "Allow":
                permissions, filters = self._extract_permissions_and_filters(
                    match, policy, request.resource
                )
                decision.decision = Decision.ALLOW if not filters else Decision.PARTIAL
                decision.permissions = permissions
                decision.filters = filters
                decision.reason = f"Allowed by policy {policy['policy_name']}"

                if policy.get("audit_config", {}).get("log_access"):
                    decision.metadata["audit_required"] = True

        return decision

    def _is_policy_valid(self, policy: Dict) -> bool:
        """Check policy validity."""
        if not policy.get("enabled", True):
            return False

        now = datetime.now(timezone.utc)

        if policy.get("not_before"):
            not_before = datetime.fromisoformat(
                policy["not_before"].replace("Z", "+00:00")
            )
            if now < not_before:
                return False

        if policy.get("not_after"):
            not_after = datetime.fromisoformat(
                policy["not_after"].replace("Z", "+00:00")
            )
            if now > not_after:
                return False

        return True

    def _match_resource(self, resource: Resource, policy: Dict) -> Optional[Dict]:
        """Match resource against policy rules."""
        if resource.type == ResourceType.CLUSTER:
            return self._match_cluster(resource, policy)

        if resource.cluster:
            cluster_match = self._match_cluster_name(resource.cluster, policy)
            if cluster_match:
                return cluster_match

        if policy.get("default_cluster_access", "none") == "allow":
            return {"permissions": {"view": True}, "filters": {}}

        return None

    def _match_cluster(self, resource: Resource, policy: Dict) -> Optional[Dict]:
        """Match cluster resource against rules."""
        for rule in policy.get("cluster_rules", []):
            selector = rule.get("cluster_selector", {})

            if "matchNames" in selector and resource.name in selector["matchNames"]:
                return rule

            if "matchPattern" in selector and re.match(
                selector["matchPattern"], resource.name
            ):
                return rule

            if "matchLabels" in selector:
                if all(
                    resource.labels.get(k) == v
                    for k, v in selector["matchLabels"].items()
                ):
                    return rule

        return None

    def _match_cluster_name(self, cluster_name: str, policy: Dict) -> Optional[Dict]:
        """Match cluster name against rules."""
        for rule in policy.get("cluster_rules", []):
            selector = rule.get("cluster_selector", {})

            if "matchNames" in selector and cluster_name in selector["matchNames"]:
                return rule

            if "matchPattern" in selector and re.match(
                selector["matchPattern"], cluster_name
            ):
                return rule

        return None

    def _extract_permissions_and_filters(
        self, rule: Dict, policy: Dict, resource: Resource
    ) -> Tuple[Set[Action], Dict[ResourceType, Filter]]:
        """Extract permissions and filters from rule."""
        perms = rule.get("permissions", {"view": True})
        permissions = set()

        permission_mapping = {
            "view": Action.VIEW,
            "viewMetrics": Action.VIEW_METRICS,
            "viewSensitive": Action.VIEW_SENSITIVE,
            "viewCosts": Action.VIEW_COSTS,
            "viewSecrets": Action.VIEW_SECRETS,
            "viewMetadata": Action.VIEW_METADATA,
            "viewAuditInfo": Action.VIEW_AUDIT,
        }

        for key, action in permission_mapping.items():
            if perms.get(key):
                permissions.add(action)

        filters = {}

        if rule.get("node_filter"):
            filters[ResourceType.NODE] = self._build_filter(rule["node_filter"])
        if rule.get("operator_filter"):
            filters[ResourceType.OPERATOR] = self._build_filter(rule["operator_filter"])
        if rule.get("namespace_filter"):
            filters[ResourceType.NAMESPACE] = self._build_filter(
                rule["namespace_filter"]
            )
        if rule.get("pod_filter"):
            filters[ResourceType.POD] = self._build_filter(rule["pod_filter"])

        return permissions, filters

    def _build_filter(self, filter_spec: Dict) -> Filter:
        """Build filter from specification."""
        visibility_str = filter_spec.get("visibility", "all")
        try:
            visibility = Visibility(visibility_str)
        except ValueError:
            visibility = Visibility.ALL

        filter_obj = Filter(visibility=visibility)

        if visibility == Visibility.NONE:
            return filter_obj

        filter_obj.include.update(filter_spec.get("allowed_literals", []))
        filter_obj.exclude.update(filter_spec.get("denied_literals", []))

        for pattern_str, pattern_regex in filter_spec.get("allowed_patterns", []):
            filter_obj.patterns.append((pattern_str, re.compile(pattern_regex)))

        filter_obj.labels.update(filter_spec.get("label_selectors", {}))
        filter_obj.metadata.update(filter_spec.get("additional_filters", {}))

        return filter_obj

    def _extract_resource_name(
        self, resource: Dict, resource_type: ResourceType
    ) -> str:
        """Extract resource identifier."""
        if resource_type == ResourceType.NODE:
            return resource.get("name", "")
        elif resource_type == ResourceType.OPERATOR:
            return resource.get("name", resource.get("display_name", ""))
        elif resource_type == ResourceType.NAMESPACE:
            return resource.get("namespace", resource.get("name", ""))
        return resource.get("name", "")

    def _apply_data_filters(
        self, resource: Dict, resource_type: ResourceType, permissions: Set[Action]
    ) -> Dict:
        """Apply data filters based on permissions."""
        filtered = resource.copy()

        sensitive_fields = {
            Action.VIEW_SENSITIVE: [
                "tokens",
                "credentials",
                "secrets",
                "certificates",
                "private_keys",
                "service_account_tokens",
                "kubeconfig",
                "password",
                "api_key",
                "auth_token",
                "bearer_token",
            ],
            Action.VIEW_COSTS: [
                "cost",
                "costs",
                "billing",
                "price",
                "prices",
                "estimated_cost",
                "monthly_cost",
                "usage_cost",
                "hourly_rate",
                "discount",
                "credits",
            ],
            Action.VIEW_SECRETS: ["secrets", "configmaps"],
            Action.VIEW_METADATA: [
                "filtered_count",
                "total_before_filter",
                "filter_reason",
                "applied_policies",
                "access_decision",
                "permission_source",
            ],
            Action.VIEW_AUDIT: [
                "audit_log",
                "access_history",
                "policy_evaluation",
                "last_accessed_by",
                "access_count",
            ],
        }

        for action, fields in sensitive_fields.items():
            if action not in permissions:
                for field in fields:
                    if field in filtered:
                        if action == Action.VIEW_SECRETS and field in [
                            "secrets",
                            "configmaps",
                        ]:
                            filtered[field] = len(filtered.get(field, []))
                        else:
                            filtered.pop(field, None)

        return filtered

    def _get_cached_decision(self, cache_key: str) -> Optional[RBACDecision]:
        """Retrieve cached decision."""
        try:
            cached = self.redis.get(cache_key)
            if cached:
                data = json.loads(cached)

                request = Request(
                    principal=Principal(**data["principal"]),
                    action=Action(data["action"]),
                    resource=Resource(
                        type=ResourceType(data["resource"]["type"]),
                        name=data["resource"]["name"],
                        namespace=data["resource"].get("namespace"),
                        cluster=data["resource"].get("cluster"),
                    ),
                )

                decision = RBACDecision(
                    decision=Decision(data["decision"]),
                    request=request,
                    reason=data["reason"],
                    permissions=set(Action(a) for a in data["permissions"]),
                    metadata=data["metadata"],
                    applied_policies=data["applied_policies"],
                )

                for resource_type_str, filter_data in data.get("filters", {}).items():
                    filter_obj = Filter()
                    filter_obj.visibility = Visibility(
                        filter_data.get("visibility", "all")
                    )
                    filter_obj.include = set(filter_data.get("include", []))
                    filter_obj.exclude = set(filter_data.get("exclude", []))
                    filter_obj.labels = filter_data.get("labels", {})
                    filter_obj.metadata = filter_data.get("metadata", {})
                    decision.filters[ResourceType(resource_type_str)] = filter_obj

                return decision
        except Exception as e:
            logger.debug(f"Cache retrieval failed: {e}")

        return None

    def _cache_decision(self, cache_key: str, decision: RBACDecision):
        """Cache authorization decision."""
        try:
            data = {
                "decision": decision.decision.value,
                "reason": decision.reason,
                "principal": {
                    "username": decision.request.principal.username,
                    "email": decision.request.principal.email,
                    "groups": decision.request.principal.groups,
                },
                "action": decision.request.action.value,
                "resource": {
                    "type": decision.request.resource.type.value,
                    "name": decision.request.resource.name,
                    "namespace": decision.request.resource.namespace,
                    "cluster": decision.request.resource.cluster,
                },
                "permissions": [a.value for a in decision.permissions],
                "metadata": decision.metadata,
                "applied_policies": decision.applied_policies,
                "filters": {},
            }

            for resource_type, filter_obj in decision.filters.items():
                data["filters"][resource_type.value] = {
                    "visibility": filter_obj.visibility.value,
                    "include": list(filter_obj.include),
                    "exclude": list(filter_obj.exclude),
                    "labels": filter_obj.labels,
                    "metadata": filter_obj.metadata,
                }

            self.redis.setex(cache_key, self.cache_ttl, json.dumps(data))
        except Exception as e:
            logger.debug(f"Cache storage failed: {e}")

    def _audit_log(self, request: Request, decision: RBACDecision):
        """Log authorization decision."""
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal": request.principal.username,
            "groups": request.principal.groups,
            "action": request.action.value,
            "resource": request.resource.id,
            "decision": decision.decision.value,
            "reason": decision.reason,
            "policies": decision.applied_policies,
            "filters": {
                rt.value: {
                    "visibility": f.visibility.value,
                    "has_filters": not f.is_empty(),
                }
                for rt, f in decision.filters.items()
            },
        }

        audit_key = f"audit:rbac:{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        self.redis.lpush(audit_key, json.dumps(audit_entry))
        self.redis.expire(audit_key, 86400 * 30)

    def create_anonymous_principal(self) -> Principal:
        """Create a principal for anonymous/unauthenticated users."""
        return Principal(
            username="anonymous",
            email="anonymous@system",
            groups=["anonymous", "public"],
            is_service_account=False,
            attributes={"anonymous": True},
        )

    def authorize_anonymous(self, action: Action, resource: Resource) -> RBACDecision:
        """Authorize anonymous access - allows viewing basic cluster health."""
        anonymous_principal = self.create_anonymous_principal()
        request = Request(
            principal=anonymous_principal, action=action, resource=resource
        )

        if action != Action.VIEW or resource.type != ResourceType.CLUSTER:
            return RBACDecision(
                decision=Decision.DENY,
                request=request,
                reason="Anonymous access only allows viewing cluster health",
            )

        return RBACDecision(
            decision=Decision.ALLOW,
            request=request,
            reason="Anonymous access to public cluster information",
            permissions={Action.VIEW},
            metadata={"anonymous": True, "restricted": True},
        )


# =============================================================================
# Factory Functions
# =============================================================================


def create_rbac_engine(redis_client: redis.Redis, cache_ttl: int = 0) -> RBACEngine:
    """Create RBAC engine instance."""
    return RBACEngine(redis_client, cache_ttl)


def principal_from_user(user: Any) -> Principal:
    """Convert user model to principal."""
    return Principal(
        username=user.username,
        email=user.email,
        groups=user.groups if hasattr(user, "groups") else [],
    )


def resource_from_cluster(cluster_name: str) -> Resource:
    """Create cluster resource."""
    return Resource(type=ResourceType.CLUSTER, name=cluster_name, cluster=cluster_name)
