# Contributing to ClusterPulse Policy Controller

> **Note:** As of v0.3.0, the policy controller has been migrated from Python/Kopf to Go using controller-runtime. It runs as a controller within the unified manager binary.

## Getting Started

### Local Setup

```bash
# Install dependencies
go mod tidy

# Set up environment
export NAMESPACE=clusterpulse
export REDIS_HOST=localhost
export REDIS_PORT=6379

# Start Redis
docker run -d -p 6379:6379 redis:latest

# Build
go build -o bin/manager ./cmd/manager/

# Run locally (connects to your current kubeconfig cluster)
./bin/manager --namespace=clusterpulse
```

### Prerequisites

- Go 1.25+
- A running Kubernetes/OpenShift cluster with CRDs installed
- Redis running and accessible
- `KUBECONFIG` set or `~/.kube/config` configured
- `controller-gen` installed (`go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest`)

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NAMESPACE` | `clusterpulse` | Namespace to watch for policies |
| `REDIS_HOST` | `redis` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | (none) | Redis password if required |
| `REDIS_DB` | `0` | Redis database number |
| `POLICY_CACHE_TTL` | `300` | Cache TTL in seconds (min: 60) |
| `GROUP_CACHE_TTL` | `300` | Group cache TTL in seconds (min: 60) |
| `MAX_POLICIES_PER_USER` | `100` | Max policies per user (min: 1) |
| `POLICY_VALIDATION_INTERVAL` | `300` | Periodic validation interval in seconds (min: 60) |

## Project Structure

The policy controller is integrated into the manager binary. Key files:

```
├── api/v1alpha1/
│   └── monitoraccesspolicy_types.go   # CRD type definitions with kubebuilder markers
├── pkg/types/
│   └── policy.go                       # Compiled policy types (snake_case JSON tags)
├── internal/
│   ├── config/
│   │   └── config.go                   # Configuration (includes policy settings)
│   ├── store/
│   │   └── policy_storage.go           # Redis storage and indexing
│   └── controller/policy/
│       ├── compiler.go                 # Policy compilation engine
│       ├── validator.go                # Lifecycle validation + periodic validator
│       └── policy_controller.go        # Reconciler (create/update/delete)
├── cmd/manager/
│   └── main.go                         # Controller registration
└── go.mod
```

## Code Generation

After modifying CRD types in `api/v1alpha1/monitoraccesspolicy_types.go`:

```bash
# Generate DeepCopy methods
controller-gen object paths="./api/v1alpha1/..."

# Generate CRD YAML
controller-gen crd paths="./api/v1alpha1/..." output:crd:dir=config/crd/bases

# Verify build
go build ./...
go vet ./...
```

## Architecture

### Controller Registration

The policy controller is registered in `cmd/manager/main.go` alongside the other three controllers:

- `PolicyReconciler` - watches MonitorAccessPolicy CRDs
- `PeriodicValidator` - runs as a manager Runnable, validates all policies on a timer
- `EvalCacheCleaner` - runs once at startup to clear stale `policy:eval:*` keys

### Reconciliation Flow

1. MonitorAccessPolicy created/updated (generation change predicate filters status-only updates)
2. `Reconcile()` fetches the CRD
3. `Compiler.Compile()` validates spec and produces a `CompiledPolicy`
4. `RedisClient.StorePolicy()` stores the compiled policy + creates all indexes
5. `ValidateCompiledPolicy()` checks lifecycle (notBefore/notAfter/enabled)
6. CRD status and Redis status both updated
7. `PublishPolicyEvent()` notifies subscribers

### Deletion Flow

1. CRD deleted or not found
2. `RedisClient.RemovePolicy()` loads existing data, removes all indexes, deletes the key
3. Evaluation caches invalidated for affected identities
4. Deletion event published

## Redis Data Format

The Redis format **must remain identical** to the Python implementation since the API reads these structures at runtime.

### Key Patterns

```
policy:{namespace}:{name}                    # Policy data (hash)
policy:user:{user}                           # User's policies (set)
policy:user:{user}:sorted                    # Sorted by priority (zset)
policy:group:{group}                         # Group's policies (set)
policy:group:{group}:sorted                  # Sorted by priority (zset)
policy:sa:{sa}                               # Service account policies (set)
policy:sa:{sa}:sorted                        # Sorted by priority (zset)
policy:customtype:{resource_type}            # Policies by custom resource type (set)
policy:customtype:{resource_type}:sorted     # Sorted by priority (zset)
policies:all                                 # All policies (set)
policies:enabled                             # Only enabled policies (set)
policies:by:priority                         # All policies by priority (zset)
policies:effect:{allow|deny}                 # Policies by effect (set)
policy:eval:{identity}:{cluster}             # Evaluation cache
user:groups:{username}                       # User's group membership
group:members:{group}                        # Group's members
user:permissions:{user}                      # User permission cache
```

### Compiled Policy JSON

The `CompiledPolicy` struct uses snake_case JSON tags matching the Python `to_dict()` output:

```json
{
  "policy_name": "dev-team-policy",
  "namespace": "clusterpulse",
  "priority": 100,
  "effect": "Allow",
  "enabled": true,
  "users": ["john.doe"],
  "groups": ["developers"],
  "service_accounts": [],
  "default_cluster_access": "none",
  "cluster_rules": [{
    "cluster_selector": {"matchNames": ["dev-*"]},
    "permissions": {"view": true},
    "node_filter": null,
    "operator_filter": null,
    "namespace_filter": {
      "visibility": "filtered",
      "allowed_patterns": [["team-a-*", "^team-a-.*$"]],
      "denied_patterns": [],
      "allowed_literals": [],
      "denied_literals": [],
      "label_selectors": {},
      "additional_filters": {}
    },
    "pod_filter": null,
    "custom_resources": {
      "pvc": {
        "resource_type_name": "pvc",
        "visibility": "filtered",
        "namespace_filter": null,
        "name_filter": null,
        "field_filters": {
          "storageClass": {
            "field_name": "storageClass",
            "allowed_patterns": [],
            "denied_patterns": [],
            "allowed_literals": ["gp3"],
            "denied_literals": [],
            "conditions": []
          }
        },
        "aggregation_rules": {"include": ["totalStorage"], "exclude": []}
      }
    }
  }],
  "not_before": null,
  "not_after": null,
  "audit_config": {"log_access": false, "require_reason": false},
  "compiled_at": "2025-01-15T10:30:00Z",
  "hash": "a1b2c3d4e5f6",
  "custom_resource_types": ["pvc"]
}
```

**Critical:** Patterns are stored as `[[original, regex], ...]` (arrays of 2-element arrays). Null for missing optional filters. `enabled` stored as lowercase string in the hash fields (`"true"`/`"false"`).

## Policy Compilation

The `Compiler` in `internal/controller/policy/compiler.go` mirrors the Python `PolicyCompiler`:

1. **Validate** - identity, access, scope required; valid effect/priority
2. **Extract subjects** - users/groups as-is, SAs → `system:serviceaccount:{ns}:{name}`
3. **Compile cluster rules** - iterate rules, compile each resource filter + custom resources
4. **Pattern compilation** - `*`→`.*`, `?`→`.`, dots escaped; literals separated from regex patterns; results cached in-memory
5. **Generate hash** - SHA-256 of canonical JSON spec, truncated to 16 hex chars

### Built-in Resource Filters

| Resource | Config Struct | Filter Struct | Pattern Prefix |
|----------|--------------|---------------|----------------|
| Nodes | `NodeResourceConfig` | `NodeFilters` (LabelSelector, HideMasters, HideByLabels) | (none) |
| Operators | `OperatorResourceConfig` | `OperatorFilters` (AllowedNamespaces, DeniedNamespaces, AllowedNames, DeniedNames) | `ns:` / `name:` |
| Namespaces | `NamespaceResourceConfig` | `NamespaceFilters` (Allowed, Denied) | (none) |
| Pods | `PodResourceConfig` | `PodFilters` (AllowedNamespaces) | (none) |

### Custom Resource Filters

The `custom` field on `PolicyResources` is a `map[string]CustomResourceConfig` where each key must match a MetricSource's `spec.rbac.resourceTypeName`. Custom resources use implicit deny — only types explicitly listed in a policy are visible.

| CRD Struct | Purpose |
|------------|---------|
| `CustomResourceConfig` | Top-level per-type config (visibility, filters, aggregations) |
| `CustomResourceFilters` | Filter container (namespaces, names, fields) |
| `PatternFilter` | Allowed/denied string patterns (shared with namespace/name filtering) |
| `FieldFilterConfig` | Per-field allowed/denied patterns + operator conditions |
| `FieldCondition` | Operator-based condition (Value is `apiextensionsv1.JSON` — polymorphic) |
| `AggregationVisibility` | Include/exclude lists for aggregation names |

Field filters can only reference fields listed in the MetricSource's `spec.rbac.filterableFields`. Supported condition operators: `equals`, `notEquals`, `contains`, `startsWith`, `endsWith`, `greaterThan`, `lessThan`, `in`, `notIn`, `matches`.

## Common Tasks

### Adding a New Policy Field

1. Add to `MonitorAccessPolicySpec` in `api/v1alpha1/monitoraccesspolicy_types.go`
2. Add to `CompiledPolicy` in `pkg/types/policy.go` (with snake_case JSON tag)
3. Handle in `Compiler.Compile()` in `internal/controller/policy/compiler.go`
4. Run `controller-gen object` and `controller-gen crd`
5. Update API to read the new field from Redis

### Adding a New Resource Filter Type

1. Add to `PolicyResources` struct in the CRD types
2. Add filter field to `CompiledClusterRule` in `pkg/types/policy.go`
3. Add `compile*Filter()` method to compiler
4. Wire it up in `compileClusterRules()`
5. Regenerate deepcopy and CRD

### Modifying Redis Storage

1. Ensure changes are backward-compatible with the Python API
2. Update `StorePolicy()` / `RemovePolicy()` in `internal/store/policy_storage.go`
3. Test with `redis-cli` to verify key format matches expectations

## Coordination with API

The policy controller and API are tightly coupled through Redis. The compiled format stored by the Go controller must match exactly what the Python API expects.

**Safe changes:** Adding optional fields with defaults in the API.
**Breaking changes:** Renaming fields, changing data types, removing fields. These require coordinated deployment.

## Debugging

```bash
# Check Redis data
redis-cli
> KEYS policy:*
> HGETALL policy:clusterpulse:dev-policy
> SMEMBERS policy:user:john.doe
> SMEMBERS policy:customtype:pvc
> ZRANGE policies:by:priority 0 -1 WITHSCORES

# Watch controller logs
kubectl logs -f -n clusterpulse deployment/cluster-controller | grep policy

# Apply test policy
kubectl apply -f examples/policy.yaml
kubectl get monitoraccesspolicies -o wide
```

## Build and Verify

```bash
# Build
go build -o bin/manager ./cmd/manager/

# Vet
go vet ./...

# Generate code
controller-gen object paths="./api/v1alpha1/..."
controller-gen crd paths="./api/v1alpha1/..." output:crd:dir=config/crd/bases
```
