"""Role-Based Access Control engine for ClusterPulse.

Provides authorization decisions for cluster resources including support for
custom MetricSource resources with namespace, name, and field-based filtering.
"""

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
    custom_type: Optional[str] = None
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        parts = [self.type.value]
        if self.custom_type:
            parts.append(self.custom_type)
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
class FieldFilter:
    """Filter configuration for a single custom resource field."""

    allowed_values: Set[str] = field(default_factory=set)
    denied_values: Set[str] = field(default_factory=set)
    allowed_patterns: List[re.Pattern] = field(default_factory=list)

    def matches(self, value: Any) -> bool:
        """Check if a field value passes this filter."""
        if value is None:
            return not self.allowed_values and not self.allowed_patterns

        str_value = str(value)

        if str_value in self.denied_values:
            return False

        if not self.allowed_values and not self.allowed_patterns:
            return True

        if str_value in self.allowed_values:
            return True

        for pattern in self.allowed_patterns:
            if pattern.match(str_value):
                return True

        return not self.allowed_values and not self.allowed_patterns

    def is_empty(self) -> bool:
        """Check if filter has no restrictions."""
        return (
            not self.allowed_values
            and not self.denied_values
            and not self.allowed_patterns
        )


@dataclass
class CustomResourceFilter:
    """Filter configuration for custom MetricSource resources."""

    namespace_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    namespace_denied: Set[str] = field(default_factory=set)
    name_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    name_denied: Set[str] = field(default_factory=set)
    field_filters: Dict[str, FieldFilter] = field(default_factory=dict)
    aggregation_include: Optional[Set[str]] = None
    aggregation_exclude: Set[str] = field(default_factory=set)

    def matches_namespace(self, namespace: Optional[str]) -> bool:
        """Check if a namespace passes the filter."""
        if namespace is None:
            return True

        if namespace in self.namespace_denied:
            return False

        if not self.namespace_patterns:
            return True

        for _, pattern in self.namespace_patterns:
            if pattern.match(namespace):
                return True

        return False

    def matches_name(self, name: str) -> bool:
        """Check if a resource name passes the filter."""
        if name in self.name_denied:
            return False

        if not self.name_patterns:
            return True

        for _, pattern in self.name_patterns:
            if pattern.match(name):
                return True

        return False

    def matches_fields(self, resource: Dict[str, Any]) -> bool:
        """Check if resource fields pass all field filters."""
        for field_name, field_filter in self.field_filters.items():
            value = resource.get(field_name)
            if not field_filter.matches(value):
                return False
        return True

    def is_empty(self) -> bool:
        """Check if filter has no restrictions."""
        return (
            not self.namespace_patterns
            and not self.namespace_denied
            and not self.name_patterns
            and not self.name_denied
            and not self.field_filters
            and self.aggregation_include is None
            and not self.aggregation_exclude
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
    custom_filters: Dict[str, CustomResourceFilter] = field(default_factory=dict)

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

    def get_custom_filter(self, resource_type_name: str) -> Optional[CustomResourceFilter]:
        """Retrieve the filter for a specific custom resource type."""
        return self.custom_filters.get(resource_type_name)


class RBACEngine:
    """RBAC authorization engine with support for custom MetricSource resources."""

    def __init__(self, redis_client: redis.Redis, cache_ttl: int = 0):
        self.redis = redis_client
        self.cache_ttl = cache_ttl
        self._policy_cache = {}
        self._cache_hits = 0
        self._cache_misses = 0
        self._caching_enabled = cache_ttl > 0

    def authorize(self, request: Request) -> RBACDecision:
        """Authorize a request."""
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

    def filter_custom_resources(
        self,
        principal: Principal,
        resources: List[Dict[str, Any]],
        resource_type_name: str,
        cluster: Optional[str],
        namespace_field: str,
        name_field: str,
        filterable_fields: List[str],
    ) -> List[Dict[str, Any]]:
        """Filter custom MetricSource resources based on RBAC policies.

        Args:
            principal: The entity making the request
            resources: List of resource dictionaries to filter
            resource_type_name: The custom resource type identifier from MetricSource
            cluster: Optional cluster name for context
            namespace_field: Field name containing namespace value
            name_field: Field name containing resource name
            filterable_fields: List of additional field names that can be filtered

        Returns:
            Filtered list of resources the principal is authorized to view
        """
        if not resources:
            return []

        dummy_resource = Resource(
            type=ResourceType.CUSTOM,
            name="*",
            cluster=cluster,
            custom_type=resource_type_name,
        )
        request = Request(
            principal=principal, action=Action.VIEW, resource=dummy_resource
        )

        decision = self.authorize(request)

        if decision.denied:
            logger.debug(
                f"Access denied for {principal.username} to custom resource "
                f"type {resource_type_name}"
            )
            return []

        custom_filter = decision.get_custom_filter(resource_type_name)

        if custom_filter is None or custom_filter.is_empty():
            if decision.decision == Decision.ALLOW:
                return resources

        if custom_filter is None:
            return resources

        filtered = []
        for resource in resources:
            namespace_value = resource.get(namespace_field)
            if not custom_filter.matches_namespace(namespace_value):
                continue

            name_value = resource.get(name_field, "")
            if not custom_filter.matches_name(name_value):
                continue

            if not custom_filter.matches_fields(resource):
                continue

            filtered.append(resource)

        logger.debug(
            f"Custom resource filtering for {principal.username} on "
            f"{resource_type_name}: {len(filtered)}/{len(resources)} allowed"
        )

        return filtered

    def get_visible_aggregations(
        self,
        principal: Principal,
        resource_type_name: str,
        cluster: str,
        all_aggregation_names: List[str],
    ) -> List[str]:
        """Get aggregation names visible to the principal.

        Args:
            principal: The entity making the request
            resource_type_name: The custom resource type identifier
            cluster: Cluster name for context
            all_aggregation_names: Complete list of available aggregation names

        Returns:
            List of aggregation names the principal is authorized to view
        """
        dummy_resource = Resource(
            type=ResourceType.CUSTOM,
            name="*",
            cluster=cluster,
            custom_type=resource_type_name,
        )
        request = Request(
            principal=principal, action=Action.VIEW, resource=dummy_resource
        )

        decision = self.authorize(request)

        if decision.denied:
            return []

        custom_filter = decision.get_custom_filter(resource_type_name)

        if custom_filter is None:
            return all_aggregation_names

        visible = set(all_aggregation_names)

        if custom_filter.aggregation_include is not None:
            visible = visible.intersection(custom_filter.aggregation_include)

        visible = visible - custom_filter.aggregation_exclude

        return list(visible)

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

            if request.resource.type == ResourceType.CUSTOM:
                custom_match = self._match_custom_resource(request, policy)
                if custom_match:
                    decision.applied_policies.append(policy["_key"])

                    if policy.get("effect") == "Deny":
                        decision.decision = Decision.DENY
                        decision.reason = f"Denied by policy {policy.get('policy_name')}"
                        break

                    custom_filter = self._extract_custom_resource_filters(
                        policy, request.resource.custom_type
                    )

                    if custom_filter:
                        decision.custom_filters[request.resource.custom_type] = custom_filter
                        decision.decision = Decision.PARTIAL
                    else:
                        decision.decision = Decision.ALLOW

                    decision.permissions.add(Action.VIEW)
                    if custom_match.get("permissions", {}).get("viewMetrics"):
                        decision.permissions.add(Action.VIEW_METRICS)

                    decision.reason = f"Allowed by policy {policy.get('policy_name')}"
                    break

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

    def _match_custom_resource(
        self, request: Request, policy: Dict
    ) -> Optional[Dict]:
        """Match a custom resource request against policy rules."""
        resource_type_name = request.resource.custom_type
        if not resource_type_name:
            return None

        for rule in policy.get("cluster_rules", []):
            custom_resources = rule.get("resources", {}).get("custom", {})
            if resource_type_name in custom_resources:
                custom_config = custom_resources[resource_type_name]
                visibility = custom_config.get("visibility", "none")

                if visibility == "none":
                    continue

                return {
                    "rule": rule,
                    "custom_config": custom_config,
                    "permissions": rule.get("permissions", {"view": True}),
                }

        return None

    def _extract_custom_resource_filters(
        self, policy: Dict, resource_type_name: str
    ) -> Optional[CustomResourceFilter]:
        """Extract custom resource filters from a policy.

        Args:
            policy: The policy dictionary
            resource_type_name: The custom resource type to extract filters for

        Returns:
            CustomResourceFilter if filters are defined, None otherwise
        """
        for rule in policy.get("cluster_rules", []):
            custom_resources = rule.get("resources", {}).get("custom", {})
            if resource_type_name not in custom_resources:
                continue

            custom_config = custom_resources[resource_type_name]
            visibility = custom_config.get("visibility", "none")

            if visibility == "none":
                return None

            if visibility == "all":
                agg_include = custom_config.get("aggregations", {}).get("include")
                agg_exclude = custom_config.get("aggregations", {}).get("exclude", [])

                if not agg_include and not agg_exclude:
                    return None

                return CustomResourceFilter(
                    aggregation_include=set(agg_include) if agg_include else None,
                    aggregation_exclude=set(agg_exclude),
                )

            custom_filter = CustomResourceFilter()
            filters_config = custom_config.get("filters", {})

            ns_config = filters_config.get("namespaces", {})
            ns_allowed = ns_config.get("allowed", [])
            ns_denied = ns_config.get("denied", [])

            for pattern_str in ns_allowed:
                try:
                    regex_pattern = self._wildcard_to_regex(pattern_str)
                    custom_filter.namespace_patterns.append(
                        (pattern_str, re.compile(regex_pattern))
                    )
                except re.error as e:
                    logger.warning(f"Invalid namespace pattern '{pattern_str}': {e}")

            custom_filter.namespace_denied = set(ns_denied)

            name_config = filters_config.get("names", {})
            name_allowed = name_config.get("allowed", [])
            name_denied = name_config.get("denied", [])

            for pattern_str in name_allowed:
                try:
                    regex_pattern = self._wildcard_to_regex(pattern_str)
                    custom_filter.name_patterns.append(
                        (pattern_str, re.compile(regex_pattern))
                    )
                except re.error as e:
                    logger.warning(f"Invalid name pattern '{pattern_str}': {e}")

            custom_filter.name_denied = set(name_denied)

            fields_config = filters_config.get("fields", {})
            for field_name, field_config in fields_config.items():
                field_filter = FieldFilter()

                allowed = field_config.get("allowed", [])
                denied = field_config.get("denied", [])
                patterns = field_config.get("patterns", [])

                field_filter.allowed_values = set(allowed)
                field_filter.denied_values = set(denied)

                for pattern_str in patterns:
                    try:
                        regex_pattern = self._wildcard_to_regex(pattern_str)
                        field_filter.allowed_patterns.append(re.compile(regex_pattern))
                    except re.error as e:
                        logger.warning(
                            f"Invalid field pattern '{pattern_str}' for {field_name}: {e}"
                        )

                if not field_filter.is_empty():
                    custom_filter.field_filters[field_name] = field_filter

            agg_config = custom_config.get("aggregations", {})
            agg_include = agg_config.get("include")
            agg_exclude = agg_config.get("exclude", [])

            if agg_include:
                custom_filter.aggregation_include = set(agg_include)
            custom_filter.aggregation_exclude = set(agg_exclude)

            return custom_filter

        return None

    def _wildcard_to_regex(self, pattern: str) -> str:
        """Convert a wildcard pattern to a regex pattern.

        Supports * for any characters and ? for single character.
        """
        escaped = re.escape(pattern)
        regex = escaped.replace(r"\*", ".*").replace(r"\?", ".")
        return f"^{regex}$"

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
                        custom_type=data["resource"].get("custom_type"),
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

                for type_name, cf_data in data.get("custom_filters", {}).items():
                    cf = CustomResourceFilter()
                    cf.namespace_denied = set(cf_data.get("namespace_denied", []))
                    cf.name_denied = set(cf_data.get("name_denied", []))

                    for pat_str in cf_data.get("namespace_patterns", []):
                        cf.namespace_patterns.append(
                            (pat_str, re.compile(self._wildcard_to_regex(pat_str)))
                        )

                    for pat_str in cf_data.get("name_patterns", []):
                        cf.name_patterns.append(
                            (pat_str, re.compile(self._wildcard_to_regex(pat_str)))
                        )

                    agg_inc = cf_data.get("aggregation_include")
                    cf.aggregation_include = set(agg_inc) if agg_inc else None
                    cf.aggregation_exclude = set(cf_data.get("aggregation_exclude", []))

                    for field_name, ff_data in cf_data.get("field_filters", {}).items():
                        ff = FieldFilter()
                        ff.allowed_values = set(ff_data.get("allowed_values", []))
                        ff.denied_values = set(ff_data.get("denied_values", []))
                        for pat_str in ff_data.get("allowed_patterns", []):
                            ff.allowed_patterns.append(
                                re.compile(self._wildcard_to_regex(pat_str))
                            )
                        cf.field_filters[field_name] = ff

                    decision.custom_filters[type_name] = cf

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
                    "custom_type": decision.request.resource.custom_type,
                },
                "permissions": [a.value for a in decision.permissions],
                "metadata": decision.metadata,
                "applied_policies": decision.applied_policies,
                "filters": {},
                "custom_filters": {},
            }

            for resource_type, filter_obj in decision.filters.items():
                data["filters"][resource_type.value] = {
                    "visibility": filter_obj.visibility.value,
                    "include": list(filter_obj.include),
                    "exclude": list(filter_obj.exclude),
                    "labels": filter_obj.labels,
                    "metadata": filter_obj.metadata,
                }

            for type_name, cf in decision.custom_filters.items():
                data["custom_filters"][type_name] = {
                    "namespace_patterns": [p[0] for p in cf.namespace_patterns],
                    "namespace_denied": list(cf.namespace_denied),
                    "name_patterns": [p[0] for p in cf.name_patterns],
                    "name_denied": list(cf.name_denied),
                    "field_filters": {
                        fn: {
                            "allowed_values": list(ff.allowed_values),
                            "denied_values": list(ff.denied_values),
                            "allowed_patterns": [
                                p.pattern for p in ff.allowed_patterns
                            ],
                        }
                        for fn, ff in cf.field_filters.items()
                    },
                    "aggregation_include": (
                        list(cf.aggregation_include)
                        if cf.aggregation_include is not None
                        else None
                    ),
                    "aggregation_exclude": list(cf.aggregation_exclude),
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

        if decision.custom_filters:
            audit_entry["custom_filters"] = {
                type_name: {
                    "has_namespace_filters": bool(cf.namespace_patterns)
                    or bool(cf.namespace_denied),
                    "has_name_filters": bool(cf.name_patterns) or bool(cf.name_denied),
                    "has_field_filters": bool(cf.field_filters),
                }
                for type_name, cf in decision.custom_filters.items()
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


def resource_from_custom(
    resource_type_name: str,
    name: str = "*",
    cluster: Optional[str] = None,
    namespace: Optional[str] = None,
) -> Resource:
    """Create a custom MetricSource resource reference.

    Args:
        resource_type_name: The resourceTypeName from MetricSource RBAC config
        name: Resource name (default "*" for collection-level access)
        cluster: Optional cluster context
        namespace: Optional namespace context

    Returns:
        Resource configured for custom resource authorization
    """
    return Resource(
        type=ResourceType.CUSTOM,
        name=name,
        cluster=cluster,
        namespace=namespace,
        custom_type=resource_type_name,
    )
