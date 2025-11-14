"""
Policy Controller for MonitorAccessPolicy CRDs
Compiles and manages RBAC policies in Redis for fast evaluation
"""

import asyncio
import atexit
import hashlib
import json
import logging
import os
import re
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple

import kopf
import redis
from kubernetes import client, config
from kubernetes.dynamic import DynamicClient
from prometheus_client import Counter, Gauge, Histogram
from redis.exceptions import RedisError

# ============================================================================
# CONSTANTS
# ============================================================================

# Environment configuration
OPERATOR_NAMESPACE = os.getenv("NAMESPACE", "clusterpulse")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_DB = int(os.getenv("REDIS_DB", 0))

# Policy settings
POLICY_CACHE_TTL = int(os.getenv("POLICY_CACHE_TTL", 300))
GROUP_CACHE_TTL = int(os.getenv("GROUP_CACHE_TTL", 300))
MAX_POLICIES_PER_USER = int(os.getenv("MAX_POLICIES_PER_USER", 100))
POLICY_VALIDATION_INTERVAL = 300  # 5 minutes

# Redis key patterns
POLICY_KEY_PATTERN = "policy:{namespace}:{name}"
USER_POLICY_KEY_PATTERN = "policy:user:{user}"
GROUP_POLICY_KEY_PATTERN = "policy:group:{group}"
SA_POLICY_KEY_PATTERN = "policy:sa:{sa}"
EVAL_CACHE_KEY_PATTERN = "policy:eval:{identity}:{cluster}"
USER_GROUPS_KEY_PATTERN = "user:groups:{username}"
GROUP_MEMBERS_KEY_PATTERN = "group:members:{group}"

# Batch processing
REDIS_SCAN_BATCH_SIZE = 100
REDIS_PIPELINE_BATCH_SIZE = 1000
CACHE_CLEAR_BATCH_SIZE = 500

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("policy-controller")

# ============================================================================
# METRICS
# ============================================================================

policy_compilation_duration = Histogram(
    "policy_compilation_duration_seconds",
    "Time spent compiling a policy",
    ["namespace", "name"],
)

cache_operations = Counter(
    "policy_cache_operations_total",
    "Total number of cache operations",
    ["operation", "result"],
)

active_policies_gauge = Gauge(
    "active_policies_total", "Total number of active policies"
)

policy_errors = Counter(
    "policy_errors_total", "Total number of policy errors", ["error_type"]
)

redis_operations = Histogram(
    "redis_operation_duration_seconds", "Redis operation duration", ["operation"]
)

# ============================================================================
# EXCEPTIONS
# ============================================================================


class PolicyError(Exception):
    """Base exception for policy-related errors"""


class PolicyCompilationError(PolicyError):
    """Error during policy compilation"""


class PolicyValidationError(PolicyError):
    """Policy validation failure"""


class PolicyStorageError(PolicyError):
    """Error storing/retrieving policy from storage"""


# ============================================================================
# ENUMS
# ============================================================================


class PolicyEffect(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"


class Visibility(str, Enum):
    ALL = "all"
    NONE = "none"
    FILTERED = "filtered"


class PolicyState(str, Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    ERROR = "Error"
    EXPIRED = "Expired"


# ============================================================================
# DATA CLASSES
# ============================================================================


@dataclass
class CompiledResourceFilter:
    """Compiled resource filter for efficient evaluation"""

    visibility: str = "all"
    allowed_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    denied_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    allowed_literals: Set[str] = field(default_factory=set)
    denied_literals: Set[str] = field(default_factory=set)
    label_selectors: Dict[str, str] = field(default_factory=dict)
    additional_filters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {
            "visibility": self.visibility,
            "allowed_patterns": [(p[0], p[1].pattern) for p in self.allowed_patterns],
            "denied_patterns": [(p[0], p[1].pattern) for p in self.denied_patterns],
            "allowed_literals": list(self.allowed_literals),
            "denied_literals": list(self.denied_literals),
            "label_selectors": self.label_selectors,
            "additional_filters": self.additional_filters,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CompiledResourceFilter":
        """Reconstruct from dictionary"""
        obj = cls(visibility=data.get("visibility", "all"))

        for pattern_str, regex_str in data.get("allowed_patterns", []):
            obj.allowed_patterns.append((pattern_str, re.compile(regex_str)))

        for pattern_str, regex_str in data.get("denied_patterns", []):
            obj.denied_patterns.append((pattern_str, re.compile(regex_str)))

        obj.allowed_literals = set(data.get("allowed_literals", []))
        obj.denied_literals = set(data.get("denied_literals", []))
        obj.label_selectors = data.get("label_selectors", {})
        obj.additional_filters = data.get("additional_filters", {})

        return obj


@dataclass
class CompiledClusterRule:
    """Compiled cluster access rule"""

    cluster_selector: Dict[str, Any]
    permissions: Dict[str, bool]
    node_filter: Optional[CompiledResourceFilter] = None
    operator_filter: Optional[CompiledResourceFilter] = None
    namespace_filter: Optional[CompiledResourceFilter] = None
    pod_filter: Optional[CompiledResourceFilter] = None

    def to_dict(self):
        return {
            "cluster_selector": self.cluster_selector,
            "permissions": self.permissions,
            "node_filter": self.node_filter.to_dict() if self.node_filter else None,
            "operator_filter": (
                self.operator_filter.to_dict() if self.operator_filter else None
            ),
            "namespace_filter": (
                self.namespace_filter.to_dict() if self.namespace_filter else None
            ),
            "pod_filter": self.pod_filter.to_dict() if self.pod_filter else None,
        }


@dataclass
class CompiledPolicy:
    """Compiled policy for efficient evaluation"""

    policy_name: str
    namespace: str
    priority: int
    effect: str
    enabled: bool

    # Subjects
    users: Set[str]
    groups: Set[str]
    service_accounts: Set[str]

    # Cluster access
    default_cluster_access: str
    cluster_rules: List[CompiledClusterRule]

    # Global restrictions
    global_restrictions: Dict[str, Any]

    # Validity
    not_before: Optional[str]
    not_after: Optional[str]

    # Audit
    audit_config: Dict[str, bool]

    # Metadata
    compiled_at: str
    hash: str

    def to_dict(self):
        """This format MUST remain unchanged for Redis compatibility"""
        return {
            "policy_name": self.policy_name,
            "namespace": self.namespace,
            "priority": self.priority,
            "effect": self.effect,
            "enabled": self.enabled,
            "users": list(self.users),
            "groups": list(self.groups),
            "service_accounts": list(self.service_accounts),
            "default_cluster_access": self.default_cluster_access,
            "cluster_rules": [r.to_dict() for r in self.cluster_rules],
            "global_restrictions": self.global_restrictions,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "audit_config": self.audit_config,
            "compiled_at": self.compiled_at,
            "hash": self.hash,
        }


# ============================================================================
# UTILITIES
# ============================================================================


class RedisBatchProcessor:
    """Efficiently batch Redis operations"""

    def __init__(self, redis_client, batch_size=REDIS_PIPELINE_BATCH_SIZE):
        self.redis = redis_client
        self.batch_size = batch_size
        self.pipeline = None
        self.operation_count = 0

    def __enter__(self):
        self.pipeline = self.redis.pipeline()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.pipeline and self.operation_count > 0:
            self.pipeline.execute()

    def add_operation(self, operation, *args, **kwargs):
        getattr(self.pipeline, operation)(*args, **kwargs)
        self.operation_count += 1

        if self.operation_count >= self.batch_size:
            self.pipeline.execute()
            self.pipeline = self.redis.pipeline()
            self.operation_count = 0

    def execute(self):
        if self.pipeline and self.operation_count > 0:
            result = self.pipeline.execute()
            self.operation_count = 0
            return result
        return []


class ResourceManager:
    """Manage resource cleanup on shutdown"""

    def __init__(self):
        self.resources = []
        atexit.register(self.cleanup)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def register(self, resource, cleanup_func):
        self.resources.append((resource, cleanup_func))

    def cleanup(self):
        for resource, cleanup_func in self.resources:
            try:
                cleanup_func(resource)
            except Exception as e:
                logger.error(f"Failed to cleanup resource: {e}")

    def _signal_handler(self, signum, frame):
        logger.info("Received shutdown signal, cleaning up...")
        self.cleanup()
        sys.exit(0)


# ============================================================================
# REDIS CONNECTION
# ============================================================================

redis_pool = redis.ConnectionPool(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    db=REDIS_DB,
    decode_responses=True,
    max_connections=50,
    socket_connect_timeout=5,
    socket_keepalive=True,
)
redis_client = redis.Redis(connection_pool=redis_pool)

# ============================================================================
# KUBERNETES CLIENT
# ============================================================================

try:
    config.load_incluster_config()
    logger.info("Loaded in-cluster Kubernetes config")
except:
    config.load_kube_config()
    logger.info("Loaded local Kubernetes config")

k8s_client = client.ApiClient()
dynamic_client = DynamicClient(k8s_client)
v1 = client.CoreV1Api()

# ============================================================================
# POLICY COMPILER
# ============================================================================


class PolicyCompiler:
    """Compiles MonitorAccessPolicy CRDs into efficient structures"""

    def compile_policy(
        self, name: str, namespace: str, spec: Dict[str, Any]
    ) -> CompiledPolicy:
        """Compile a policy spec into an efficient structure"""
        logger.info(f"Compiling policy {namespace}/{name}")

        with policy_compilation_duration.labels(namespace=namespace, name=name).time():
            try:
                # Validate the new format spec
                self._validate_spec(spec)

                # Extract components from new format
                identity = spec.get("identity", {})
                access = spec.get("access", {})
                scope = spec.get("scope", {})
                lifecycle = spec.get("lifecycle", {})
                operations = spec.get("operations", {})

                # Extract subjects
                subjects = self._extract_subjects(identity.get("subjects", {}))

                # Compile cluster rules
                cluster_rules = self._compile_cluster_rules(scope.get("clusters", {}))

                # Extract validity
                validity = self._extract_validity(lifecycle.get("validity", {}))

                # Extract audit config
                audit_config = self._extract_audit_config(operations.get("audit", {}))

                # Generate policy hash
                policy_hash = self._generate_hash(spec)

                # Return the EXACT SAME compiled format for Redis compatibility
                return CompiledPolicy(
                    policy_name=name,
                    namespace=namespace,
                    priority=identity.get("priority", 100),
                    effect=access.get("effect", "Allow"),
                    enabled=access.get("enabled", True),
                    users=subjects["users"],
                    groups=subjects["groups"],
                    service_accounts=subjects["service_accounts"],
                    default_cluster_access=scope.get("clusters", {}).get(
                        "default", "none"
                    ),
                    cluster_rules=cluster_rules,
                    global_restrictions=scope.get("restrictions", {}),
                    not_before=validity["not_before"],
                    not_after=validity["not_after"],
                    audit_config=audit_config,
                    compiled_at=datetime.now(timezone.utc).isoformat(),
                    hash=policy_hash,
                )

            except Exception as e:
                policy_errors.labels(error_type="compilation").inc()
                raise PolicyCompilationError(f"Failed to compile policy: {str(e)}")

    def _validate_spec(self, spec: Dict[str, Any]):
        """Validate policy specification (new format)"""
        if not isinstance(spec, dict):
            raise PolicyValidationError("Policy spec must be a dictionary")

        # Check required sections
        if "identity" not in spec:
            raise PolicyValidationError("Policy must have an 'identity' section")

        if "access" not in spec:
            raise PolicyValidationError("Policy must have an 'access' section")

        if "scope" not in spec:
            raise PolicyValidationError("Policy must have a 'scope' section")

        # Validate identity section
        identity = spec.get("identity", {})
        if "subjects" not in identity:
            raise PolicyValidationError("Identity section must specify subjects")

        # Validate access section
        access = spec.get("access", {})
        effect = access.get("effect", "Allow")
        if effect not in ["Allow", "Deny"]:
            raise PolicyValidationError(f"Invalid effect: {effect}")

        # Validate priority
        priority = identity.get("priority", 100)
        if not isinstance(priority, int) or priority < 0:
            raise PolicyValidationError(f"Invalid priority: {priority}")

    def _extract_subjects(self, subjects: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract and process subjects"""
        users = set(subjects.get("users", []))
        groups = set(subjects.get("groups", []))

        # Process service accounts
        service_accounts = set()
        for sa in subjects.get("serviceAccounts", []):
            sa_namespace = sa.get("namespace", "default")
            sa_name = sa["name"]
            service_accounts.add(f"system:serviceaccount:{sa_namespace}:{sa_name}")

        return {"users": users, "groups": groups, "service_accounts": service_accounts}

    def _compile_cluster_rules(
        self, clusters: Dict[str, Any]
    ) -> List[CompiledClusterRule]:
        """Compile cluster access rules from new format"""
        rules = []

        for rule in clusters.get("rules", []):
            # Extract selector, permissions, and resources
            selector = rule.get("selector", {})
            permissions = rule.get("permissions", {"view": True})
            resources = rule.get("resources", {})

            # Compile resource filters
            node_filter = None
            operator_filter = None
            namespace_filter = None
            pod_filter = None

            # Process nodes
            if "nodes" in resources:
                node_config = resources["nodes"]
                node_filter = self._compile_node_filter(
                    node_config.get("visibility", "all"), node_config.get("filters", {})
                )

            # Process operators
            if "operators" in resources:
                op_config = resources["operators"]
                operator_filter = self._compile_operator_filter(
                    op_config.get("visibility", "all"), op_config.get("filters", {})
                )

            # Process namespaces
            if "namespaces" in resources:
                ns_config = resources["namespaces"]
                namespace_filter = self._compile_namespace_filter(
                    ns_config.get("visibility", "all"), ns_config.get("filters", {})
                )

            # Process pods
            if "pods" in resources:
                pod_config = resources["pods"]
                pod_filter = self._compile_pod_filter(
                    pod_config.get("visibility", "all"), pod_config.get("filters", {})
                )

            compiled_rule = CompiledClusterRule(
                cluster_selector=selector,
                permissions=permissions,
                node_filter=node_filter,
                operator_filter=operator_filter,
                namespace_filter=namespace_filter,
                pod_filter=pod_filter,
            )

            rules.append(compiled_rule)

        return rules

    def _compile_node_filter(
        self, visibility: str, filters: Dict
    ) -> CompiledResourceFilter:
        """Compile node-specific filters"""
        filter_obj = CompiledResourceFilter(visibility=visibility)

        # Add label selector
        if "labelSelector" in filters:
            filter_obj.label_selectors = filters["labelSelector"]

        # Add node-specific filters
        if filters.get("hideMasters"):
            filter_obj.additional_filters["hide_masters"] = True

        if "hideByLabels" in filters:
            filter_obj.additional_filters["hide_by_labels"] = filters["hideByLabels"]

        return filter_obj

    def _compile_operator_filter(
        self, visibility: str, filters: Dict
    ) -> CompiledResourceFilter:
        """Compile operator-specific filters"""
        filter_obj = CompiledResourceFilter(visibility=visibility)

        # Process namespace filters
        for pattern in filters.get("allowedNamespaces", []):
            compiled = self._compile_pattern(pattern)
            if compiled[0] == "literal":
                filter_obj.allowed_literals.add(f"ns:{compiled[1]}")
            else:
                filter_obj.allowed_patterns.append((f"ns:{pattern}", compiled[1]))

        for pattern in filters.get("deniedNamespaces", []):
            compiled = self._compile_pattern(pattern)
            if compiled[0] == "literal":
                filter_obj.denied_literals.add(f"ns:{compiled[1]}")
            else:
                filter_obj.denied_patterns.append((f"ns:{pattern}", compiled[1]))

        # Process name filters
        for pattern in filters.get("allowedNames", []):
            compiled = self._compile_pattern(pattern)
            if compiled[0] == "literal":
                filter_obj.allowed_literals.add(f"name:{compiled[1]}")
            else:
                filter_obj.allowed_patterns.append((f"name:{pattern}", compiled[1]))

        for pattern in filters.get("deniedNames", []):
            compiled = self._compile_pattern(pattern)
            if compiled[0] == "literal":
                filter_obj.denied_literals.add(f"name:{compiled[1]}")
            else:
                filter_obj.denied_patterns.append((f"name:{pattern}", compiled[1]))

        return filter_obj

    def _compile_namespace_filter(
        self, visibility: str, filters: Dict
    ) -> CompiledResourceFilter:
        """Compile namespace filters"""
        filter_obj = CompiledResourceFilter(visibility=visibility)

        # Process allowed patterns/literals
        for pattern in filters.get("allowed", []):
            compiled = self._compile_pattern(pattern)
            if compiled[0] == "literal":
                filter_obj.allowed_literals.add(compiled[1])
            else:
                filter_obj.allowed_patterns.append((pattern, compiled[1]))

        # Process denied patterns/literals
        for pattern in filters.get("denied", []):
            compiled = self._compile_pattern(pattern)
            if compiled[0] == "literal":
                filter_obj.denied_literals.add(compiled[1])
            else:
                filter_obj.denied_patterns.append((pattern, compiled[1]))

        return filter_obj

    def _compile_pod_filter(
        self, visibility: str, filters: Dict
    ) -> CompiledResourceFilter:
        """Compile pod filters"""
        filter_obj = CompiledResourceFilter(visibility=visibility)

        # Process allowed namespaces for pods
        for pattern in filters.get("allowedNamespaces", []):
            compiled = self._compile_pattern(pattern)
            if compiled[0] == "literal":
                filter_obj.allowed_literals.add(compiled[1])
            else:
                filter_obj.allowed_patterns.append((pattern, compiled[1]))

        return filter_obj

    @lru_cache(maxsize=1024)
    def _compile_pattern(self, pattern: str) -> Tuple[str, Any]:
        """Compile a string pattern into regex or literal (cached)"""
        if "*" in pattern or "?" in pattern:
            # Convert shell-style wildcards to regex
            regex_pattern = pattern.replace(".", r"\.")
            regex_pattern = regex_pattern.replace("*", ".*")
            regex_pattern = regex_pattern.replace("?", ".")
            return ("regex", re.compile(f"^{regex_pattern}$"))
        else:
            return ("literal", pattern)

    def _extract_validity(self, validity: Dict[str, Any]) -> Dict[str, Optional[str]]:
        """Extract validity period"""
        return {
            "not_before": validity.get("notBefore"),
            "not_after": validity.get("notAfter"),
        }

    def _extract_audit_config(self, audit: Dict[str, Any]) -> Dict[str, bool]:
        """Extract audit configuration"""
        return {
            "log_access": audit.get("logAccess", False),
            "require_reason": audit.get("requireReason", False),
        }

    def _generate_hash(self, spec: Dict[str, Any]) -> str:
        """Generate hash of the policy spec"""
        spec_json = json.dumps(spec, sort_keys=True)
        return hashlib.sha256(spec_json.encode()).hexdigest()[:16]


# ============================================================================
# POLICY STORE
# ============================================================================


class PolicyStore:
    """Manages policy storage and indexing in Redis"""

    def __init__(self, redis_client):
        self.redis = redis_client

    def store_policy(self, policy: CompiledPolicy):
        """Store compiled policy in Redis with indexes"""
        policy_key = POLICY_KEY_PATTERN.format(
            namespace=policy.namespace, name=policy.policy_name
        )

        with redis_operations.labels(operation="store_policy").time():
            with RedisBatchProcessor(self.redis) as batch:
                # Store the main policy data
                policy_data = json.dumps(policy.to_dict())
                batch.add_operation(
                    "hset",
                    policy_key,
                    mapping={
                        "data": policy_data,
                        "priority": policy.priority,
                        "effect": policy.effect,
                        "enabled": str(policy.enabled).lower(),
                        "hash": policy.hash,
                        "compiled_at": policy.compiled_at,
                    },
                )

                # Create indexes
                self._create_policy_indexes(batch, policy, policy_key)

        # Clear evaluation caches
        self._invalidate_evaluation_caches(
            policy.users, policy.groups, policy.service_accounts
        )

        # Update metrics
        active_policies_gauge.inc()

        logger.info(f"Stored policy {policy_key} and cleared evaluation caches")

    def _create_policy_indexes(
        self, batch: RedisBatchProcessor, policy: CompiledPolicy, policy_key: str
    ):
        """Create all indexes for a policy"""
        # Index by users
        for user in policy.users:
            if policy.enabled:
                batch.add_operation(
                    "sadd", USER_POLICY_KEY_PATTERN.format(user=user), policy_key
                )
                batch.add_operation(
                    "zadd",
                    f"{USER_POLICY_KEY_PATTERN.format(user=user)}:sorted",
                    {policy_key: policy.priority},
                )

        # Index by groups
        for group in policy.groups:
            if policy.enabled:
                batch.add_operation(
                    "sadd", GROUP_POLICY_KEY_PATTERN.format(group=group), policy_key
                )
                batch.add_operation(
                    "zadd",
                    f"{GROUP_POLICY_KEY_PATTERN.format(group=group)}:sorted",
                    {policy_key: policy.priority},
                )

        # Index by service accounts
        for sa in policy.service_accounts:
            if policy.enabled:
                batch.add_operation(
                    "sadd", SA_POLICY_KEY_PATTERN.format(sa=sa), policy_key
                )
                batch.add_operation(
                    "zadd",
                    f"{SA_POLICY_KEY_PATTERN.format(sa=sa)}:sorted",
                    {policy_key: policy.priority},
                )

        # Global indexes
        batch.add_operation("sadd", "policies:all", policy_key)
        batch.add_operation(
            "zadd", "policies:by:priority", {policy_key: policy.priority}
        )

        if policy.enabled:
            batch.add_operation("sadd", "policies:enabled", policy_key)

        batch.add_operation(
            "sadd", f"policies:effect:{policy.effect.lower()}", policy_key
        )

    def remove_policy(self, namespace: str, name: str):
        """Remove policy and all its indexes"""
        policy_key = POLICY_KEY_PATTERN.format(namespace=namespace, name=name)

        # Get policy data first
        policy_data = self.redis.hget(policy_key, "data")
        if not policy_data:
            logger.warning(f"Policy {policy_key} not found for removal")
            return

        policy = json.loads(policy_data)

        with redis_operations.labels(operation="remove_policy").time():
            with RedisBatchProcessor(self.redis) as batch:
                self._remove_policy_indexes(batch, policy, policy_key)
                batch.add_operation("delete", policy_key)

        # Clear evaluation caches
        self._invalidate_evaluation_caches(
            policy.get("users", []),
            policy.get("groups", []),
            policy.get("service_accounts", []),
        )

        # Publish event
        self._publish_policy_event("deleted", namespace, name)

        # Update metrics
        active_policies_gauge.dec()

        logger.info(f"Removed policy {policy_key} and cleared evaluation caches")

    def _remove_policy_indexes(
        self, batch: RedisBatchProcessor, policy: Dict, policy_key: str
    ):
        """Remove all indexes for a policy"""
        # Remove from user indexes
        for user in policy.get("users", []):
            batch.add_operation(
                "srem", USER_POLICY_KEY_PATTERN.format(user=user), policy_key
            )
            batch.add_operation(
                "zrem",
                f"{USER_POLICY_KEY_PATTERN.format(user=user)}:sorted",
                policy_key,
            )

        # Remove from group indexes
        for group in policy.get("groups", []):
            batch.add_operation(
                "srem", GROUP_POLICY_KEY_PATTERN.format(group=group), policy_key
            )
            batch.add_operation(
                "zrem",
                f"{GROUP_POLICY_KEY_PATTERN.format(group=group)}:sorted",
                policy_key,
            )

        # Remove from service account indexes
        for sa in policy.get("service_accounts", []):
            batch.add_operation("srem", SA_POLICY_KEY_PATTERN.format(sa=sa), policy_key)
            batch.add_operation(
                "zrem", f"{SA_POLICY_KEY_PATTERN.format(sa=sa)}:sorted", policy_key
            )

        # Remove from global indexes
        batch.add_operation("srem", "policies:all", policy_key)
        batch.add_operation("zrem", "policies:by:priority", policy_key)
        batch.add_operation("srem", "policies:enabled", policy_key)
        batch.add_operation(
            "srem",
            f"policies:effect:{policy.get('effect', 'allow').lower()}",
            policy_key,
        )

    def _invalidate_evaluation_caches(
        self, users: List[str], groups: List[str], service_accounts: List[str]
    ):
        """Invalidate evaluation caches for affected identities using SCAN"""
        count = 0

        with RedisBatchProcessor(self.redis) as batch:
            # Clear caches for users
            for user in users:
                pattern = f"policy:eval:{user}:*"
                count += self._scan_and_delete(batch, pattern)
                batch.add_operation("delete", f"user:permissions:{user}")

            # Clear caches for groups and their members
            for group in groups:
                # Get group members
                members = self.redis.smembers(
                    GROUP_MEMBERS_KEY_PATTERN.format(group=group)
                )
                for member in members:
                    pattern = f"policy:eval:{member}:*"
                    count += self._scan_and_delete(batch, pattern)
                    batch.add_operation("delete", f"user:permissions:{member}")

                # Clear group-specific caches
                pattern = f"policy:eval:*:group:{group}:*"
                count += self._scan_and_delete(batch, pattern)

            # Clear service account caches
            for sa in service_accounts:
                pattern = f"policy:eval:{sa}:*"
                count += self._scan_and_delete(batch, pattern)

        cache_operations.labels(operation="invalidate", result="success").inc(count)
        logger.debug(f"Cleared {count} evaluation cache entries")

    def _scan_and_delete(self, batch: RedisBatchProcessor, pattern: str) -> int:
        """Scan for keys matching pattern and delete them"""
        count = 0
        cursor = 0

        while True:
            cursor, keys = self.redis.scan(
                cursor, match=pattern, count=REDIS_SCAN_BATCH_SIZE
            )

            for key in keys:
                batch.add_operation("delete", key)
                count += 1

            if cursor == 0:
                break

        return count

    def _publish_policy_event(self, action: str, namespace: str, name: str):
        """Publish policy change event"""
        event = {
            "action": action,
            "policy": f"{namespace}/{name}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self.redis.publish("policy-changes", json.dumps(event))
        self.redis.publish(
            "policy-events",
            json.dumps(
                {
                    "type": f"policy.{action}",
                    "policy": f"{namespace}/{name}",
                    "timestamp": event["timestamp"],
                }
            ),
        )

    def update_policy_status(self, namespace: str, name: str, status: Dict[str, Any]):
        """Update policy status in Redis"""
        policy_key = POLICY_KEY_PATTERN.format(namespace=namespace, name=name)
        self.redis.hset(policy_key, "status", json.dumps(status))

    def get_policy(self, namespace: str, name: str) -> Optional[Dict]:
        """Retrieve a policy from storage"""
        policy_key = POLICY_KEY_PATTERN.format(namespace=namespace, name=name)

        try:
            data = self.redis.hget(policy_key, "data")
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve policy {policy_key}: {e}")
            raise PolicyStorageError(f"Failed to retrieve policy: {str(e)}")

    def list_policies(self, enabled_only: bool = False) -> List[str]:
        """List all policies or only enabled ones"""
        key = "policies:enabled" if enabled_only else "policies:all"
        return list(self.redis.smembers(key))


# ============================================================================
# POLICY VALIDATOR
# ============================================================================


class PolicyValidator:
    """Validates policies for expiration and other conditions"""

    def __init__(self, policy_store: PolicyStore):
        self.policy_store = policy_store

    async def validate_policy(
        self, namespace: str, name: str, spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate a policy and return its status"""
        status = {
            "state": PolicyState.ACTIVE,
            "message": "Policy is active",
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Check validity period from lifecycle section
        lifecycle = spec.get("lifecycle", {})
        validity = lifecycle.get("validity", {})
        now = datetime.now(timezone.utc)

        if validity.get("notBefore"):
            not_before = datetime.fromisoformat(
                validity["notBefore"].replace("Z", "+00:00")
            )
            if now < not_before:
                status["state"] = PolicyState.INACTIVE
                status["message"] = (
                    f'Policy not yet valid (starts at {validity["notBefore"]})'
                )
                return status

        if validity.get("notAfter"):
            not_after = datetime.fromisoformat(
                validity["notAfter"].replace("Z", "+00:00")
            )
            if now > not_after:
                status["state"] = PolicyState.EXPIRED
                status["message"] = f'Policy expired at {validity["notAfter"]}'
                return status

        # Check if enabled from access section
        access = spec.get("access", {})
        if not access.get("enabled", True):
            status["state"] = PolicyState.INACTIVE
            status["message"] = "Policy is disabled"

        return status

    async def validate_all_policies(self):
        """Validate all policies for expiration"""
        policies = self.policy_store.list_policies()

        for policy_key in policies:
            try:
                # Parse policy key
                parts = policy_key.split(":")
                if len(parts) >= 3:
                    namespace = parts[1]
                    name = parts[2]

                    # Get policy data
                    policy_data = self.policy_store.get_policy(namespace, name)
                    if policy_data:
                        # Note: This retrieves the compiled format from Redis
                        # May need to reconstruct the spec or store it separately
                        # For now, validate based on the compiled data
                        status = {
                            "state": PolicyState.ACTIVE,
                            "message": "Policy is active",
                            "validated_at": datetime.now(timezone.utc).isoformat(),
                        }

                        now = datetime.now(timezone.utc)

                        if policy_data.get("not_before"):
                            not_before = datetime.fromisoformat(
                                policy_data["not_before"].replace("Z", "+00:00")
                            )
                            if now < not_before:
                                status["state"] = PolicyState.INACTIVE
                                status["message"] = f"Policy not yet valid"

                        if policy_data.get("not_after"):
                            not_after = datetime.fromisoformat(
                                policy_data["not_after"].replace("Z", "+00:00")
                            )
                            if now > not_after:
                                status["state"] = PolicyState.EXPIRED
                                status["message"] = f"Policy expired"

                        if not policy_data.get("enabled", True):
                            status["state"] = PolicyState.INACTIVE
                            status["message"] = "Policy is disabled"

                        self.policy_store.update_policy_status(namespace, name, status)

                        if status["state"] == PolicyState.EXPIRED:
                            logger.info(f"Policy {namespace}/{name} has expired")

            except Exception as e:
                logger.error(f"Error validating policy {policy_key}: {e}")


# ============================================================================
# INITIALIZATION
# ============================================================================

policy_store = PolicyStore(redis_client)
policy_compiler = PolicyCompiler()
policy_validator = PolicyValidator(policy_store)

# ============================================================================
# KOPF HANDLERS (Using new format exclusively)
# ============================================================================


@kopf.on.create("clusterpulse.io", "v1alpha1", "monitoraccesspolicies")
@kopf.on.update("clusterpulse.io", "v1alpha1", "monitoraccesspolicies")
async def policy_changed(
    name: str,
    namespace: str,
    spec: Dict[str, Any],
    meta: Dict[str, Any],
    patch: Dict,
    **kwargs,
):
    """Handle policy creation or updates"""
    logger.info(f"Policy {namespace}/{name} changed")

    try:
        # Compile the policy (new format only)
        spec_dict = dict(spec)
        compiled = policy_compiler.compile_policy(name, namespace, spec_dict)

        # Store in Redis (exactly the same format as before)
        policy_store.store_policy(compiled)

        # Validate the policy
        status = await policy_validator.validate_policy(namespace, name, spec_dict)

        # Add compilation info to status
        status.update(
            {
                "compiledAt": compiled.compiled_at,
                "affectedUsers": len(compiled.users),
                "affectedGroups": len(compiled.groups),
                "affectedServiceAccounts": len(compiled.service_accounts),
                "hash": compiled.hash,
            }
        )

        # Update status
        patch["status"] = status
        policy_store.update_policy_status(namespace, name, status)

        logger.info(f"Successfully compiled policy {namespace}/{name}")

    except PolicyCompilationError as e:
        logger.error(f"Failed to compile policy {namespace}/{name}: {str(e)}")

        patch["status"] = {
            "state": PolicyState.ERROR,
            "message": f"Compilation failed: {str(e)}",
            "error_at": datetime.now(timezone.utc).isoformat(),
        }

        policy_store.update_policy_status(namespace, name, patch["status"])

    except Exception as e:
        logger.error(
            f"Unexpected error handling policy {namespace}/{name}: {str(e)}",
            exc_info=True,
        )

        patch["status"] = {
            "state": PolicyState.ERROR,
            "message": f"Unexpected error: {str(e)}",
            "error_at": datetime.now(timezone.utc).isoformat(),
        }

        policy_store.update_policy_status(namespace, name, patch["status"])


@kopf.on.delete("clusterpulse.io", "v1alpha1", "monitoraccesspolicies")
async def policy_deleted(name: str, namespace: str, **kwargs):
    """Handle policy deletion"""
    logger.info(f"Policy {namespace}/{name} deleted")

    try:
        policy_store.remove_policy(namespace, name)
        logger.info(f"Successfully removed policy {namespace}/{name}")

    except Exception as e:
        logger.error(f"Error deleting policy {namespace}/{name}: {str(e)}")
        policy_errors.labels(error_type="deletion").inc()


@kopf.timer(
    "clusterpulse.io",
    "v1alpha1",
    "monitoraccesspolicies",
    interval=POLICY_VALIDATION_INTERVAL,
)
async def periodic_policy_validation(
    name: str,
    namespace: str,
    spec: Dict[str, Any],
    status: Dict[str, Any],
    patch: Dict,
    **kwargs,
):
    """Periodic validation of policies"""
    try:
        # Validate the policy
        new_status = await policy_validator.validate_policy(namespace, name, dict(spec))

        # Check if status changed
        current_state = status.get("state")
        new_state = new_status["state"]

        if current_state != new_state:
            logger.info(
                f"Policy {namespace}/{name} state changed from {current_state} to {new_state}"
            )

            # Update status
            patch["status"] = new_status
            policy_store.update_policy_status(namespace, name, new_status)

            # If policy became inactive/expired, update indexes
            if new_state in [PolicyState.INACTIVE, PolicyState.EXPIRED]:
                policy_key = POLICY_KEY_PATTERN.format(namespace=namespace, name=name)
                redis_client.srem("policies:enabled", policy_key)

    except Exception as e:
        logger.error(f"Error validating policy {namespace}/{name}: {str(e)}")
        policy_errors.labels(error_type="validation").inc()


# ============================================================================
# STARTUP AND SHUTDOWN
# ============================================================================


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    """Configure kopf settings"""
    settings.batching.worker_limit = 3
    settings.posting.enabled = False
    settings.watching.server_timeout = 300
    settings.watching.client_timeout = 310
    settings.watching.connect_timeout = 10
    settings.persistence.finalizer = "clusterpulse.io/finalizer"
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix="clusterpulse.io"
    )
    settings.execution.max_workers = 3
    settings.batching.idle_timeout = 1.0
    settings.batching.batch_window = 0.5

    logger.info("Kopf configured with API server protection settings")


@kopf.on.startup()
async def startup_handler(**kwargs):
    """Startup tasks"""
    logger.info("Policy controller starting up")

    # Initialize resource manager
    global resource_manager
    resource_manager = ResourceManager()

    try:
        redis_client.ping()
        logger.info("Redis connection successful")

        # Clear stale evaluation caches on startup
        count = 0
        cursor = 0
        pattern = "policy:eval:*"

        while True:
            cursor, keys = redis_client.scan(
                cursor, match=pattern, count=REDIS_SCAN_BATCH_SIZE
            )
            if keys:
                redis_client.delete(*keys)
                count += len(keys)
            if cursor == 0:
                break

        logger.info(f"Cleared {count} evaluation cache entries on startup")

        # Initialize metrics
        active_policies_gauge.set(redis_client.scard("policies:enabled"))

    except RedisError as e:
        logger.error(f"Failed to connect to Redis: {str(e)}")
        sys.exit(1)

    # Start background tasks
    asyncio.create_task(periodic_cache_cleanup())

    logger.info("Policy controller ready")


async def periodic_cache_cleanup():
    """Periodically clean up expired caches"""
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour

            # Clear expired evaluation caches
            count = 0
            cursor = 0
            pattern = "policy:eval:*"
            time.time()

            while True:
                cursor, keys = redis_client.scan(
                    cursor, match=pattern, count=REDIS_SCAN_BATCH_SIZE
                )

                for key in keys:
                    ttl = redis_client.ttl(key)
                    if ttl == -1:  # No expiry set
                        redis_client.expire(key, POLICY_CACHE_TTL)
                        count += 1

                if cursor == 0:
                    break

            if count > 0:
                logger.info(f"Set expiry on {count} cache entries without TTL")

        except Exception as e:
            logger.error(f"Error in cache cleanup: {e}")


@kopf.on.cleanup()
async def cleanup_handler(**kwargs):
    """Cleanup tasks"""
    logger.info("Policy controller shutting down")

    # Close Redis connection pool
    redis_pool.disconnect()


@kopf.on.probe(id="health")
async def health_probe(**kwargs):
    """Health check probe"""
    try:
        redis_client.ping()

        return {
            "status": "healthy",
            "policies": redis_client.scard("policies:all"),
            "enabled_policies": redis_client.scard("policies:enabled"),
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import time

    kopf.run(
        namespace=OPERATOR_NAMESPACE, liveness_endpoint="http://0.0.0.0:8080/healthz"
    )
