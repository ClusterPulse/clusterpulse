# Contributing to ClusterPulse Policy Controller

## Getting Started

### Local Setup

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies (uses uv.lock for reproducible builds)
cd policy-controller
uv sync

# Set up environment
export NAMESPACE=clusterpulse
export REDIS_HOST=localhost
export REDIS_PORT=6379

# Start Redis
docker run -d -p 6379:6379 redis:latest

# Run locally (connects to your current kubeconfig cluster)
uv run python policy_controller.py
```

### Running Locally

The policy controller can be run locally for development and testing. It will connect to whatever Kubernetes cluster your kubeconfig is pointing to.

**Prerequisites:**
- A running Kubernetes/OpenShift cluster with the MonitorAccessPolicy CRD installed
- Redis running and accessible
- `KUBECONFIG` set or `~/.kube/config` configured

**Running with kopf:**

```bash
cd policy-controller

# Run with default settings
uv run python policy_controller.py

# Run with verbose logging
uv run kopf run policy_controller.py --verbose

# Run in standalone mode (no leader election)
uv run kopf run policy_controller.py --standalone

# Run watching a specific namespace
uv run kopf run policy_controller.py --namespace=clusterpulse
```

**Environment variables for local development:**

| Variable | Default | Description |
|----------|---------|-------------|
| `NAMESPACE` | `clusterpulse` | Namespace to watch for policies |
| `REDIS_HOST` | `redis` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | (none) | Redis password if required |
| `REDIS_DB` | `0` | Redis database number |
| `POLICY_CACHE_TTL` | `300` | Cache TTL in seconds |

### Development Dependencies

Development and test dependencies are included in `pyproject.toml` and managed by uv:

```bash
# Install all dependencies including dev/test
uv sync

# Or install only production dependencies
uv sync --no-dev
```

## Project Structure

The policy-controller is a single Python file organized into logical sections. Here's what each part does.

### File Organization

```
policy-controller/
├── policy_controller.py    # Main controller (all sections below)
├── pyproject.toml          # Python project configuration
├── uv.lock                  # Locked dependencies for reproducible builds
└── tests/                   # Tests (TODO)
```

### Code Sections in `policy_controller.py`

The file is organized into these sections (in order):

#### 1. Constants & Configuration
Environment variables and Redis key patterns.

**What's here:**
- Environment configuration (REDIS_HOST, NAMESPACE, etc.)
- Policy settings (cache TTL, validation intervals)
- Redis key patterns for storing policies and indexes
- Batch processing constants

**When to edit:**
- Adding new environment variables
- Changing default values
- Adding new Redis key patterns
- Adjusting batch sizes

```python
# Example: Adding a new configuration
POLICY_MAX_SIZE = int(os.getenv("POLICY_MAX_SIZE", 100000))  # bytes
```

#### 2. Logging
Basic logging configuration.

```python
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("policy-controller")
```

#### 3. Metrics
Prometheus metrics for monitoring policy operations.

**Available metrics:**
- `policy_compilation_duration_seconds` - Time to compile a policy
- `policy_cache_operations_total` - Cache operations counter
- `active_policies_total` - Number of active policies
- `policy_errors_total` - Error counter by type
- `redis_operation_duration_seconds` - Redis operation timings

**When to add:**
- New performance metrics
- New error types to track
- New cache operations

```python
# Example: Adding a new metric
policy_validations = Counter(
    "policy_validations_total",
    "Total policy validations",
    ["result"]
)
```

#### 4. Exceptions
Custom exception hierarchy for policy errors.

```python
class PolicyError(Exception): pass
class PolicyCompilationError(PolicyError): pass
class PolicyValidationError(PolicyError): pass
class PolicyStorageError(PolicyError): pass
```

#### 5. Enums
Type-safe constants for policy effects, visibility, and states.

```python
class PolicyEffect(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"

class PolicyState(str, Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    ERROR = "Error"
    EXPIRED = "Expired"
```

#### 6. Data Classes
Compiled policy structures for efficient evaluation.

**Key classes:**
- `CompiledResourceFilter` - Compiled resource filters (namespaces, nodes, operators, pods)
- `CompiledClusterRule` - Cluster access rules with filters
- `CompiledPolicy` - Complete compiled policy ready for Redis

**Critical:** These classes define the Redis storage format. Changes here impact the API's RBAC engine.

```python
@dataclass
class CompiledPolicy:
    policy_name: str
    namespace: str
    priority: int
    effect: str
    enabled: bool
    users: Set[str]
    groups: Set[str]
    service_accounts: Set[str]
    cluster_rules: List[CompiledClusterRule]
    # ... more fields
    
    def to_dict(self):
        """This format MUST remain unchanged for Redis compatibility"""
        return {...}
```

**Important:** The `to_dict()` method creates the format that the API reads. Any changes must be coordinated with API changes.

#### 7. Utilities
Helper classes for batch processing and resource management.

**RedisBatchProcessor:**
Efficiently batches Redis operations to avoid network overhead.

```python
with RedisBatchProcessor(redis_client, batch_size=1000) as batch:
    for item in items:
        batch.add_operation("set", key, value)
    # Auto-executes on context exit
```

**ResourceManager:**
Handles cleanup on shutdown (signal handlers, atexit).

#### 8. Redis Connection
Connection pool for Redis client.

```python
redis_pool = redis.ConnectionPool(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
    max_connections=50,
)
redis_client = redis.Redis(connection_pool=redis_pool)
```

#### 9. Kubernetes Client
Connection to the Kubernetes API.

```python
config.load_incluster_config()  # In cluster
# or
config.load_kube_config()  # Local dev

k8s_client = client.ApiClient()
dynamic_client = DynamicClient(k8s_client)
```

#### 10. Policy Compiler
Compiles MonitorAccessPolicy CRDs into efficient structures.

**Main method:**
```python
def compile_policy(name: str, namespace: str, spec: Dict) -> CompiledPolicy
```

**What it does:**
1. Validates the policy spec (new format)
2. Extracts subjects (users, groups, service accounts)
3. Compiles cluster rules with resource filters
4. Processes patterns into regex or literals
5. Extracts validity periods and audit config
6. Generates a hash for change detection
7. Returns a CompiledPolicy object

**Pattern compilation:**
- Literal strings stored as-is for fast lookup
- Wildcards (`*`, `?`) compiled to regex
- Results cached with `@lru_cache`

```python
@lru_cache(maxsize=1024)
def _compile_pattern(self, pattern: str) -> Tuple[str, Any]:
    if "*" in pattern or "?" in pattern:
        # Convert to regex
        return ("regex", re.compile(f"^{regex_pattern}$"))
    else:
        return ("literal", pattern)
```

#### 11. Policy Store
Manages policy storage and indexing in Redis.

**Main methods:**
- `store_policy(policy)` - Store compiled policy with indexes
- `remove_policy(namespace, name)` - Remove policy and indexes
- `_invalidate_evaluation_caches(...)` - Clear caches for affected users/groups

**Redis structure:**
```
policy:{namespace}:{name}              # Policy data (hash)
policy:user:{user}                     # User's policies (set)
policy:user:{user}:sorted              # Sorted by priority (zset)
policy:group:{group}                   # Group's policies (set)
policy:group:{group}:sorted            # Sorted by priority (zset)
policy:sa:{sa}                         # Service account policies (set)
policies:all                           # All policies (set)
policies:enabled                       # Only enabled policies (set)
policies:by:priority                   # All policies by priority (zset)
policy:eval:{identity}:{cluster}       # Evaluation cache
user:groups:{username}                 # User's group membership
group:members:{group}                  # Group's members
```

**Indexing strategy:**
- Policies indexed by user, group, and service account
- Priority-sorted sets for efficient lookup
- Global indexes for all policies
- Evaluation caches for performance

**Cache invalidation:**
When a policy changes, all affected evaluation caches must be cleared:
```python
def _invalidate_evaluation_caches(self, users, groups, service_accounts):
    # Clear user caches
    # Clear group member caches
    # Clear service account caches
    # Uses SCAN to find and delete matching keys
```

#### 12. Policy Validator
Validates policies for expiration and conditions.

**Main methods:**
- `validate_policy(namespace, name, spec)` - Validate single policy
- `validate_all_policies()` - Periodic validation of all policies

**Validation checks:**
- `notBefore` date - Policy not yet valid
- `notAfter` date - Policy expired
- `enabled` flag - Policy disabled

```python
async def validate_policy(self, namespace, name, spec):
    now = datetime.now(timezone.utc)
    
    if validity.get("notBefore"):
        not_before = datetime.fromisoformat(...)
        if now < not_before:
            return {"state": "Inactive", "message": "Not yet valid"}
    
    if validity.get("notAfter"):
        not_after = datetime.fromisoformat(...)
        if now > not_after:
            return {"state": "Expired", "message": "Policy expired"}
```

#### 13. Kopf Handlers
Kubernetes operator event handlers using kopf framework.

**Handlers:**

**`@kopf.on.create` / `@kopf.on.update`**
- Triggered when MonitorAccessPolicy is created/updated
- Compiles the policy
- Stores in Redis
- Validates and updates status

**`@kopf.on.delete`**
- Triggered when MonitorAccessPolicy is deleted
- Removes from Redis
- Clears all indexes

**`@kopf.timer`**
- Periodic validation (every 5 minutes)
- Checks for expired policies
- Updates status if state changed

**`@kopf.on.startup`**
- Initializes Redis connection
- Clears stale caches
- Starts background tasks

**`@kopf.on.cleanup`**
- Closes Redis connection
- Cleanup on shutdown

**`@kopf.on.probe`**
- Health check endpoint
- Returns policy counts

## Understanding Policy Compilation

Policy compilation is the core function. Here's how it works:

### Input: MonitorAccessPolicy CRD

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: dev-team-policy
  namespace: clusterpulse
spec:
  identity:
    priority: 100
    subjects:
      users: ["john.doe", "jane.smith"]
      groups: ["developers"]
  access:
    effect: Allow
    enabled: true
  scope:
    clusters:
      default: none
      rules:
        - selector:
            names: ["dev-*"]
          permissions:
            view: true
            viewMetrics: true
          resources:
            namespaces:
              visibility: filtered
              filters:
                allowed: ["team-a-*", "shared-*"]
```

### Compilation Process

1. **Validation:**
   - Check required sections (identity, access, scope)
   - Validate effect (Allow/Deny)
   - Validate priority (must be >= 0)

2. **Extract Subjects:**
   ```python
   users = set(["john.doe", "jane.smith"])
   groups = set(["developers"])
   service_accounts = set()  # Converted to k8s format
   ```

3. **Compile Cluster Rules:**
   - Process each rule's selector and permissions
   - Compile resource filters (namespaces, nodes, operators, pods)
   - Convert patterns to regex or literals

4. **Pattern Compilation:**
   ```python
   "team-a-*" → regex: ^team-a-.*$
   "shared-prod" → literal: "shared-prod"
   ```

5. **Generate Hash:**
   - Hash the entire spec for change detection
   - Used by API to detect policy changes

### Output: CompiledPolicy in Redis

```python
{
    "policy_name": "dev-team-policy",
    "namespace": "clusterpulse",
    "priority": 100,
    "effect": "Allow",
    "enabled": True,
    "users": ["john.doe", "jane.smith"],
    "groups": ["developers"],
    "cluster_rules": [
        {
            "cluster_selector": {"names": ["dev-*"]},
            "permissions": {"view": True, "viewMetrics": True},
            "namespace_filter": {
                "visibility": "filtered",
                "allowed_patterns": [("team-a-*", "^team-a-.*$")],
                "allowed_literals": [],
                ...
            }
        }
    ],
    "compiled_at": "2025-01-15T10:30:00Z",
    "hash": "a1b2c3d4e5f6"
}
```

### Redis Storage and Indexing

When stored, the policy is indexed multiple ways:

```
# Main policy data
SET policy:clusterpulse:dev-team-policy {...}

# Index by users
SADD policy:user:john.doe policy:clusterpulse:dev-team-policy
ZADD policy:user:john.doe:sorted 100 policy:clusterpulse:dev-team-policy

# Index by groups
SADD policy:group:developers policy:clusterpulse:dev-team-policy
ZADD policy:group:developers:sorted 100 policy:clusterpulse:dev-team-policy

# Global indexes
SADD policies:all policy:clusterpulse:dev-team-policy
SADD policies:enabled policy:clusterpulse:dev-team-policy
ZADD policies:by:priority 100 policy:clusterpulse:dev-team-policy
```

This allows the API to quickly find all policies for a user/group sorted by priority.

## Common Tasks

### Adding a New Policy Field

1. **Update the validation:**

```python
def _validate_spec(self, spec: Dict[str, Any]):
    # Add validation for new field
    if "newSection" in spec:
        new_value = spec["newSection"].get("newField")
        if new_value and not isinstance(new_value, str):
            raise PolicyValidationError("newField must be a string")
```

2. **Extract the field during compilation:**

```python
def compile_policy(self, name: str, namespace: str, spec: Dict) -> CompiledPolicy:
    # Extract new field
    new_section = spec.get("newSection", {})
    new_value = new_section.get("newField", "default")
    
    # Add to compiled policy
    return CompiledPolicy(
        # ... existing fields
        new_field=new_value,
    )
```

3. **Add to CompiledPolicy dataclass:**

```python
@dataclass
class CompiledPolicy:
    # ... existing fields
    new_field: str
    
    def to_dict(self):
        return {
            # ... existing fields
            "new_field": self.new_field,
        }
```

4. **Update the CRD** (in another repository):
   - Add the field to the OpenAPI schema
   - Update examples and documentation

### Adding a New Resource Filter Type

If you need to filter a new resource type (e.g., ConfigMaps):

1. **Add compilation method:**

```python
def _compile_configmap_filter(
    self, visibility: str, filters: Dict
) -> CompiledResourceFilter:
    """Compile configmap-specific filters"""
    filter_obj = CompiledResourceFilter(visibility=visibility)
    
    # Process namespace filters
    for pattern in filters.get("allowedNamespaces", []):
        compiled = self._compile_pattern(pattern)
        if compiled[0] == "literal":
            filter_obj.allowed_literals.add(compiled[1])
        else:
            filter_obj.allowed_patterns.append((pattern, compiled[1]))
    
    # Add configmap-specific filters
    if "maxDataSize" in filters:
        filter_obj.additional_filters["max_data_size"] = filters["maxDataSize"]
    
    return filter_obj
```

2. **Add to cluster rules compilation:**

```python
def _compile_cluster_rules(self, clusters: Dict) -> List[CompiledClusterRule]:
    # ... existing code
    
    # Process configmaps
    if "configmaps" in resources:
        cm_config = resources["configmaps"]
        configmap_filter = self._compile_configmap_filter(
            cm_config.get("visibility", "all"),
            cm_config.get("filters", {})
        )
```

3. **Add field to CompiledClusterRule:**

```python
@dataclass
class CompiledClusterRule:
    # ... existing fields
    configmap_filter: Optional[CompiledResourceFilter] = None
    
    def to_dict(self):
        return {
            # ... existing fields
            "configmap_filter": (
                self.configmap_filter.to_dict() if self.configmap_filter else None
            ),
        }
```

### Adding a New Validation Rule

1. **Add to `_validate_spec`:**

```python
def _validate_spec(self, spec: Dict[str, Any]):
    # ... existing validations
    
    # New validation
    scope = spec.get("scope", {})
    restrictions = scope.get("restrictions", {})
    
    if "maxClusters" in restrictions:
        max_clusters = restrictions["maxClusters"]
        if not isinstance(max_clusters, int) or max_clusters < 1:
            raise PolicyValidationError("maxClusters must be >= 1")
```

2. **Use during compilation:**

```python
def compile_policy(self, name, namespace, spec):
    try:
        self._validate_spec(spec)
        # ... continue compilation
    except PolicyValidationError as e:
        policy_errors.labels(error_type="validation").inc()
        raise
```

### Changing Cache Invalidation Logic

When policies change, caches must be cleared. To modify this:

```python
def _invalidate_evaluation_caches(self, users, groups, service_accounts):
    count = 0
    
    with RedisBatchProcessor(self.redis) as batch:
        # Clear user caches
        for user in users:
            pattern = f"policy:eval:{user}:*"
            count += self._scan_and_delete(batch, pattern)
            
            # Add new cache type
            batch.add_operation("delete", f"user:computed_permissions:{user}")
        
        # ... rest of invalidation
```

### Adding a New Metric

```python
# At top of file with other metrics
policy_size_bytes = Histogram(
    "policy_size_bytes",
    "Size of compiled policies in bytes",
    ["namespace"]
)

# Use in code
def store_policy(self, policy: CompiledPolicy):
    policy_data = json.dumps(policy.to_dict())
    
    # Record metric
    policy_size_bytes.labels(namespace=policy.namespace).observe(len(policy_data))
    
    # Store in Redis
    # ...
```

### Modifying Periodic Validation

The timer handler runs every 5 minutes by default:

```python
@kopf.timer(
    "clusterpulse.io",
    "v1alpha1",
    "monitoraccesspolicies",
    interval=300,  # Change this value
)
async def periodic_policy_validation(...):
    # Validation logic
```

To make it configurable:

```python
# Add to constants
POLICY_VALIDATION_INTERVAL = int(os.getenv("POLICY_VALIDATION_INTERVAL", 300))

# Use in handler
@kopf.timer(
    "clusterpulse.io",
    "v1alpha1",
    "monitoraccesspolicies",
    interval=POLICY_VALIDATION_INTERVAL,
)
```

## Testing

Tests should cover:

1. **Policy compilation:**
   - Valid policy specs compile correctly
   - Invalid specs raise appropriate errors
   - Pattern compilation (literals vs regex)
   - Filter compilation for each resource type

2. **Redis storage:**
   - Policies stored with correct indexes
   - Cache invalidation clears correct keys
   - Batch operations work correctly

3. **Validation:**
   - Time-based validation (notBefore, notAfter)
   - Enabled/disabled flag handling
   - State transitions

4. **Kopf handlers:**
   - Create/update handlers compile and store
   - Delete handler removes all traces
   - Status updates work correctly

**Test pattern:** - TODO

```python
import pytest
import fakeredis
from policy_controller import PolicyCompiler, PolicyStore

@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)

def test_compile_basic_policy():
    compiler = PolicyCompiler()
    
    spec = {
        "identity": {
            "priority": 100,
            "subjects": {"users": ["test.user"]}
        },
        "access": {"effect": "Allow", "enabled": True},
        "scope": {
            "clusters": {"default": "none", "rules": []}
        }
    }
    
    policy = compiler.compile_policy("test", "default", spec)
    
    assert policy.policy_name == "test"
    assert policy.priority == 100
    assert "test.user" in policy.users
    assert policy.enabled is True
```

See `docs/api/tests.md` for more testing patterns.

### Running Tests

```bash
# All tests
uv run pytest

# Specific category
uv run pytest -m unit
uv run pytest -m integration

# With coverage
uv run pytest --cov=. --cov-report=html

# Single test
uv run pytest tests/test_compiler.py::test_compile_basic_policy -v
```

## Code Patterns

### Error Handling

Always wrap errors with context:

```python
try:
    compiled = policy_compiler.compile_policy(name, namespace, spec)
except PolicyValidationError as e:
    policy_errors.labels(error_type="validation").inc()
    raise PolicyCompilationError(f"Failed to compile {namespace}/{name}: {str(e)}")
```

Use specific exception types:

```python
if not isinstance(spec, dict):
    raise PolicyValidationError("Policy spec must be a dictionary")

if redis_error:
    raise PolicyStorageError(f"Failed to store policy: {str(error)}")
```

### Logging

Use appropriate log levels:

```python
# Info - important state changes
logger.info(f"Stored policy {policy_key} and cleared evaluation caches")

# Debug - detailed operations
logger.debug(f"Cleared {count} evaluation cache entries")

# Warning - unusual but handled
logger.warning(f"Policy {policy_key} not found for removal")

# Error - actual problems
logger.error(f"Failed to compile policy {namespace}/{name}: {str(e)}")
```

### Redis Operations

Use batch operations for efficiency:

```python
with RedisBatchProcessor(self.redis, batch_size=1000) as batch:
    for user in policy.users:
        batch.add_operation("sadd", user_key, policy_key)
        batch.add_operation("zadd", sorted_key, {policy_key: priority})
```

Use SCAN for large key sets:

```python
cursor = 0
while True:
    cursor, keys = self.redis.scan(
        cursor, match=pattern, count=REDIS_SCAN_BATCH_SIZE
    )
    for key in keys:
        batch.add_operation("delete", key)
    if cursor == 0:
        break
```

### Pattern Compilation

Cache compiled patterns:

```python
@lru_cache(maxsize=1024)
def _compile_pattern(self, pattern: str) -> Tuple[str, Any]:
    if "*" in pattern or "?" in pattern:
        regex_pattern = pattern.replace(".", r"\.")
        regex_pattern = regex_pattern.replace("*", ".*")
        regex_pattern = regex_pattern.replace("?", ".")
        return ("regex", re.compile(f"^{regex_pattern}$"))
    else:
        return ("literal", pattern)
```

Separate literals from patterns for performance:

```python
for pattern in filters.get("allowed", []):
    compiled = self._compile_pattern(pattern)
    if compiled[0] == "literal":
        filter_obj.allowed_literals.add(compiled[1])  # Fast set lookup
    else:
        filter_obj.allowed_patterns.append((pattern, compiled[1]))  # Regex match
```

### Status Updates

Update status in handlers:

```python
@kopf.on.update("clusterpulse.io", "v1alpha1", "monitoraccesspolicies")
async def policy_changed(name, namespace, spec, patch, **kwargs):
    try:
        compiled = policy_compiler.compile_policy(name, namespace, spec)
        policy_store.store_policy(compiled)
        
        # Success status
        patch["status"] = {
            "state": "Active",
            "compiledAt": compiled.compiled_at,
            "hash": compiled.hash,
        }
    except PolicyCompilationError as e:
        # Error status
        patch["status"] = {
            "state": "Error",
            "message": str(e),
            "error_at": datetime.now(timezone.utc).isoformat(),
        }
```

### Dataclass Serialization

Ensure Redis compatibility:

```python
def to_dict(self):
    """This format MUST remain unchanged for Redis compatibility"""
    return {
        "policy_name": self.policy_name,
        "users": list(self.users),  # Convert sets to lists
        "groups": list(self.groups),
        "cluster_rules": [r.to_dict() for r in self.cluster_rules],  # Nested
        "compiled_at": self.compiled_at,  # ISO format string
    }

@classmethod
def from_dict(cls, data: Dict) -> "CompiledResourceFilter":
    """Reconstruct from Redis data"""
    obj = cls(visibility=data.get("visibility", "all"))
    
    # Reconstruct compiled patterns
    for pattern_str, regex_str in data.get("allowed_patterns", []):
        obj.allowed_patterns.append((pattern_str, re.compile(regex_str)))
    
    obj.allowed_literals = set(data.get("allowed_literals", []))
    return obj
```

## Performance Considerations

### Batch Operations

Always batch Redis operations:

```python
# DON'T - N individual operations
for key in keys:
    redis_client.delete(key)

# DO - Single pipeline
with RedisBatchProcessor(redis_client) as batch:
    for key in keys:
        batch.add_operation("delete", key)
```

### Pattern Compilation Caching

The `@lru_cache` decorator caches compiled patterns:

```python
@lru_cache(maxsize=1024)
def _compile_pattern(self, pattern: str):
    # This result is cached - subsequent calls with same pattern are instant
```

### SCAN Instead of KEYS

Use SCAN for large keysets to avoid blocking:

```python
# DON'T - Blocks Redis
keys = redis_client.keys("policy:eval:*")

# DO - Iterative scan
cursor = 0
while True:
    cursor, keys = redis_client.scan(cursor, match="policy:eval:*", count=100)
    # Process keys
    if cursor == 0:
        break
```

### Parallel Operations

Use `asyncio` for parallel validation:

```python
async def validate_all_policies(self):
    policies = self.policy_store.list_policies()
    
    # Process in batches
    tasks = []
    for policy_key in policies:
        task = self.validate_single_policy(policy_key)
        tasks.append(task)
    
    await asyncio.gather(*tasks, return_exceptions=True)
```

### Metrics Collection Overhead

Metrics are lightweight but add up. Use labels wisely:

```python
# Good - Few label values
policy_errors.labels(error_type="validation").inc()

# Bad - Too many unique label combinations
policy_errors.labels(
    namespace=namespace,
    name=name,
    error_type=type,
    user=user,
    cluster=cluster
).inc()
```

## Common Pitfalls

1. **Breaking Redis compatibility:**
   ```python
   # ❌ Wrong - Changes API expects
   def to_dict(self):
       return {
           "policyName": self.policy_name,  # Should be policy_name
           "users": self.users,              # Should be list(self.users)
       }
   
   # ✅ Right
   def to_dict(self):
       return {
           "policy_name": self.policy_name,
           "users": list(self.users),
       }
   ```

2. **Not invalidating caches:**
   ```python
   # ❌ Wrong - API will serve stale decisions
   def store_policy(self, policy):
       self.redis.set(policy_key, data)
       # Forgot to clear caches!
   
   # ✅ Right
   def store_policy(self, policy):
       self.redis.set(policy_key, data)
       self._invalidate_evaluation_caches(
           policy.users, policy.groups, policy.service_accounts
       )
   ```

3. **Using KEYS instead of SCAN:**
   ```python
   # ❌ Wrong - Blocks Redis on large datasets
   keys = redis_client.keys("policy:eval:*")
   
   # ✅ Right
   def _scan_and_delete(self, batch, pattern):
       cursor = 0
       while True:
           cursor, keys = self.redis.scan(cursor, match=pattern, count=100)
           # Process keys
           if cursor == 0:
               break
   ```

4. **Not handling None values:**
   ```python
   # ❌ Wrong - Will crash on None
   allowed = filters["allowed"]
   
   # ✅ Right
   allowed = filters.get("allowed", [])
   ```

5. **Forgetting to update status:**
   ```python
   # ❌ Wrong - User doesn't see compilation errors
   @kopf.on.update(...)
   async def policy_changed(name, namespace, spec, **kwargs):
       compiled = compiler.compile_policy(name, namespace, spec)
       # No status update!
   
   # ✅ Right
   @kopf.on.update(...)
   async def policy_changed(name, namespace, spec, patch, **kwargs):
       try:
           compiled = compiler.compile_policy(name, namespace, spec)
           patch["status"] = {"state": "Active", ...}
       except Exception as e:
           patch["status"] = {"state": "Error", "message": str(e)}
   ```

6. **Not using batch processor context manager:**
   ```python
   # ❌ Wrong - Manual execution
   batch = RedisBatchProcessor(redis_client)
   batch.add_operation("set", key, value)
   batch.execute()  # Easy to forget!
   
   # ✅ Right - Auto-executes
   with RedisBatchProcessor(redis_client) as batch:
       batch.add_operation("set", key, value)
   ```

7. **Storing sets directly in JSON:**
   ```python
   # ❌ Wrong - Sets aren't JSON serializable
   json.dumps({"users": policy.users})
   
   # ✅ Right - Convert to list
   json.dumps({"users": list(policy.users)})
   ```

## Code Style

Use `black` for formatting:

```bash
uv run black policy_controller.py
```

Use `autoflake` to remove unused imports and variables

```bash
uv run autoflake --remove-all-unused-imports --remove-unused-variables --recursive --in-place policy_controller.py
```

Use `isort` to sort imports

```bash
uv run isort policy_controller.py
```

Use type hints:

```python
def compile_policy(
    self, name: str, namespace: str, spec: Dict[str, Any]
) -> CompiledPolicy:
    # Implementation
```

Docstrings for public methods:

```python
def store_policy(self, policy: CompiledPolicy):
    """Store compiled policy in Redis with indexes
    
    Args:
        policy: The compiled policy to store
        
    Raises:
        PolicyStorageError: If Redis operation fails
    """
```

## Pull Request Process

1. **Branch naming:** `feature/add-configmap-filter` or `fix/cache-invalidation`

2. **Commits:**
   - ✅ "Add ConfigMap resource filter support"
   - ✅ "Fix cache invalidation for service accounts"
   - ❌ "WIP" or "Fix stuff"

3. **Before submitting:**
   ```bash
   # Format code
   uv run black policy_controller.py
   
   # Run tests - TODO
   uv run pytest tests/
   
   # Check types
   uv run mypy policy_controller.py
   
   # Test with real CRD
   oc apply -f examples/policy.yaml
   ```

4. **PR description should include:**
   - What changed and why
   - Redis format changes (critical!)
   - Impact on API RBAC engine
   - How to test it

5. **Things reviewers look for:**
   - Redis format compatibility maintained
   - Cache invalidation is correct
   - Status updates on errors
   - Batch operations used
   - Metrics added for new operations
   - Tests cover new functionality

## Coordination with API

The policy-controller and API are tightly coupled through Redis:

**Policy Controller writes:**
```python
{
    "policy_name": "dev-policy",
    "users": ["user1"],
    "cluster_rules": [...],
}
```

**API reads:**
```python
# api/services/rbac.py
policy_data = redis.hget(policy_key, "data")
policy = json.loads(policy_data)
users = policy["users"]
```

**Critical:** Any change to the compiled format requires coordinated deployment:
1. Update policy-controller code
2. Update API RBAC engine code
3. Deploy policy-controller first
4. Recompile all policies (triggers update handlers)
5. Deploy API

**Safe changes:**
- Adding optional fields (with defaults in API)
- Adding new filter types (ignored if API doesn't check)
- Adding metrics

**Breaking changes:**
- Renaming fields
- Changing data types
- Removing fields

## Quick Reference

### Environment Variables

```bash
NAMESPACE=clusterpulse                 # Operator namespace
REDIS_HOST=redis                       # Redis host
REDIS_PORT=6379                        # Redis port
REDIS_PASSWORD=                        # Redis password (optional)
POLICY_CACHE_TTL=300                   # Cache TTL in seconds
POLICY_VALIDATION_INTERVAL=300         # Validation interval
MAX_POLICIES_PER_USER=100              # User policy limit
```

### Common Redis Keys

```
policy:{namespace}:{name}              # Policy data
policy:user:{user}                     # User's policies
policy:group:{group}                   # Group's policies
policy:eval:{identity}:{cluster}       # Evaluation cache
user:groups:{username}                 # User's groups
```

### Useful Commands

```bash
# Development
cd policy-controller
uv run python policy_controller.py

# Testing - TODO
uv run pytest tests/

# Format
uv run black policy_controller.py

# Remove unused imports
uv run autoflake --remove-all-unused-imports --remove-unused-variables --recursive --in-place <path>

# Sort imports
uv run isort <path>

# Check Redis
redis-cli
> KEYS policy:*
> HGETALL policy:clusterpulse:dev-policy
> SMEMBERS policy:user:john.doe

# Watch logs
oc logs -f -n clusterpulse deployment/policy-controller
```

### Kopf Commands

```bash
# Run with debug logging
uv run kopf run policy_controller.py --verbose

# Run in standalone mode (no leader election)
uv run kopf run policy_controller.py --standalone

# Configure namespace
uv run kopf run policy_controller.py --namespace=clusterpulse
```

## Getting Help

- Review RBAC engine in API (`api/services/rbac.py`) to understand usage
- Read kopf documentation: https://kopf.readthedocs.io
- Check Redis data directly with `redis-cli` to debug storage issues
- Look at Prometheus metrics for performance insights

## Project-Specific Notes

- **Single file architecture:** All code in one file, organized by sections
- **Redis is the contract:** Format cannot change without API coordination
- **Kopf framework:** Uses decorators for event handlers
- **Batch everything:** Redis operations should use pipelines
- **Cache invalidation is critical:** Stale caches cause incorrect authorization
- **Pattern compilation is cached:** Same patterns reused across policies
- **Status updates in CRD:** Users see compilation errors/success in oc
- **Metrics for observability:** All operations instrumented with Prometheus
