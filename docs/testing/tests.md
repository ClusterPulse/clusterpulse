# Go Test Suite

## Overview

The Go test suite covers the core operator services: expression engine, aggregation, field extraction, metric source compilation, RBAC engine/types/cache/filter, API handlers with RBAC integration, controllers, ingester, store layer, collector utilities, config loading, and utility parsing. Tests use standard library `testing` only (no testify/gomock). Redis is mocked with `miniredis/v2`.

## Quick Start

```bash
# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Run with coverage
go test -cover ./...
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

## Test Inventory

### Pure Function Tests (no external dependencies)

| Package | File | Tests | What It Covers |
|---------|------|-------|----------------|
| `pkg/utils` | `parser_test.go` | 41 | CPU/memory string parsing |
| `pkg/utils` | `circuit_breaker_test.go` | 6 | Circuit breaker state machine |
| `internal/metricsource/expression` | `tokenizer_test.go` | 25 | Lexical analysis (operators, strings, numbers, keywords) |
| `internal/metricsource/expression` | `parser_test.go` | 20 | AST building, precedence, functions, Compile/ExtractReferences |
| `internal/metricsource/expression` | `evaluator_test.go` | 35 | Expression evaluation, type coercion, short-circuit logic |
| `internal/metricsource/expression` | `functions_test.go` | 40 | All 20 built-in functions + toString/toFloat helpers |
| `internal/metricsource/aggregator` | `filter_test.go` | 20 | All 9 filter operators + regex caching |
| `internal/metricsource/aggregator` | `aggregator_test.go` | 25 | All 7 aggregation functions + grouping + filtering |
| `internal/metricsource/extractor` | `extractor_test.go` | 30 | Path navigation, type conversion, field extraction |
| `internal/metricsource/compiler` | `compiler_test.go` | 30 | Validation, helpers (parseAPIVersion, pluralize, etc.) |
| `internal/config` | `config_test.go` | 15 | Env var parsing (getEnv, getEnvInt, getEnvBool, getEnvIntWithMin) |
| `internal/collector` | `buffer_test.go` | 10 | Bounded FIFO buffer with concurrent access |
| `internal/collector` | `agent_test.go` | 13 | toFloat64, extractNodeMetrics, strVal, applyConfig, extractOperatorProto, extractClusterOperatorProto |
| `internal/rbac` | `types_test.go` | 20 | Principal/Resource/Request cache keys, MatchSpec, RBACDecision, CustomResourceDecision |
| `internal/rbac` | `engine_test.go` | 35 | RBAC engine security, FilterResources, evaluatePolicies (deny/disabled/default), matchCluster, matchesResource, aggregation rules, helpers |
| `internal/rbac` | `filter_test.go` | 12 | buildMatcherFromCompiled, filter helpers, pattern compilation |
| `internal/api` | `handlers_test.go` | 5 | HealthHandler + writeJSON |
| `internal/api` | `aggregations_test.go` | 22 | getFieldValue, matchesFilter, computeSingle, computeGrouped, toFloat |
| `internal/api` | `config_test.go` | 8 | envStr, envInt, envBool, isDevelopment |
| `internal/api` | `clusters_helpers_test.go` | 11 | paginate, queryInt, getStringSliceFromMap |
| `internal/api` | `custom_types_helpers_test.go` | 3 | extractNames |
| `internal/api` | `middleware_test.go` | 5 | getPrincipal, securityHeaders, resolveGroups |
| `internal/controller/policy` | `compiler_test.go` | 18 | Policy compilation, subject extraction, permissions |
| `internal/controller/policy` | `validator_test.go` | 6 | Policy validation, lifecycle parsing |
| `internal/ingester` | `handler_test.go` | 8 | Proto-to-internal type conversions |
| `internal/ingester` | `vmwriter_test.go` | 4 | formatLine, boolToInt, VMWriter.Send |
| `internal/ingester` | `server_tls_test.go` | 2 | TLS cert/key loading |
| `internal/ingester` | `server_test.go` | 3 | Connection tracking lifecycle, heartbeat |

### Controller Tests (pure helper methods)

| Package | File | Tests | What It Covers |
|---------|------|-------|----------------|
| `internal/client/cluster` | `client_test.go` | 14 | deriveConsoleURL, getStringValue, extractNodeMetrics (ready/unschedulable/notReady/noPods), extractClusterOperatorInfo, extractOperatorInfo, getLastUsed |
| `internal/client/registry` | `client_test.go` | 15 | NewDockerV2Client, HealthCheck (OK/401/500/refused/auth), CheckCatalog (OK/maxEntries/error), detectRegistryInfo, ExtendedHealthCheck |
| `internal/metricsource/collector` | `collector_test.go` | 8 | filterNamespaces (nil/include/exclude/combined/wildcards) |
| `internal/version` | `version_test.go` | 1 | Default build variable values |
| `internal/controller/cluster` | `cluster_controller_test.go` | 6 | getReconcileInterval, statusEqual, countAvailable, countDegraded |
| `internal/controller/registry` | `registry_controller_test.go` | 12 | getReconcileInterval, calculateRegistryHealth, shouldUpdateStatus, generateHealthMessage, mapsEqual |

### Miniredis-Backed Tests (store layer + RBAC cache)

| Package | File | Tests | What It Covers |
|---------|------|-------|----------------|
| `internal/store` | `client_test.go` | 20 | StoreOperators, StoreNodeMetrics, StoreClusterMetrics, StoreNamespaces, StoreClusterInfo/Status/Spec/Labels, StoreClusterOperators, PublishEvent, DeleteClusterData |
| `internal/store` | `policy_storage_test.go` | 15 | StorePolicy indexes, GetPolicy round-trip, RemovePolicy, ListPolicies, UpdatePolicyStatus, InvalidateEvaluationCaches, PublishPolicyEvent |
| `internal/store` | `metricsource_storage_test.go` | 12 | StoreCompiledMetricSource, GetCompiledMetricSourceByID, DeleteMetricSource, ListMetricSources, StoreCustomResourceCollection, StoreAggregationResults |
| `internal/store` | `registry_storage_test.go` | 8 | StoreRegistrySpec/Status/Metrics, GetRegistryStatus, GetAllRegistries, DeleteRegistryData |
| `internal/store` | `resource_storage_test.go` | 4 | StoreResourceCollection |
| `internal/store` | `reader_test.go` | 16 | GetJSON, GetJSONList, GetHashJSON, GetClusterBundle, GetAllClusterNames, GetClusterNodes, GetNodeMetricsHistory, GetPoliciesForPrincipal |
| `internal/rbac` | `cache_test.go` | 16 | NewCache, Get/SetDecision, ClearDecisions, Get/SetCustomDecision, DTO converter round-trips |

### API Integration Tests (miniredis + httptest)

| Package | File | Tests | What It Covers |
|---------|------|-------|----------------|
| `internal/api` | `handlers_readyz_test.go` | 2 | ReadyHandler with Redis up/down |
| `internal/api` | `middleware_integration_test.go` | 7 | AuthMiddleware, OptionalAuthMiddleware, SecurityHeaders |
| `internal/api` | `auth_handler_test.go` | 8 | AuthStatus, GetMe, GetPermissions, Logout, ClearCache |
| `internal/api` | `clusters_handler_test.go` | 6 | ListClusters, GetCluster (accessible/denied), GetClusterNodes |
| `internal/api` | `registries_handler_test.go` | 3 | ListRegistriesStatus (unauth, empty, with data) |
| `internal/api` | `custom_types_handler_test.go` | 5 | ListCustomTypes, GetCustomResourceCounts |

### Ingester Integration Tests (miniredis)

| Package | File | Tests | What It Covers |
|---------|------|-------|----------------|
| `internal/ingester` | `handler_integration_test.go` | 6 | ProcessBatch (cluster/node/info/custom), BuildConfigUpdate |

## Testing with External Dependencies

### Redis (miniredis)

Tests that require Redis use `github.com/alicebob/miniredis/v2` which provides an in-memory Redis server. No real Redis instance is needed.

```go
import "github.com/alicebob/miniredis/v2"

func TestSomething(t *testing.T) {
    mr := miniredis.RunT(t) // auto-cleaned up
    // Use mr.Addr() to connect
}
```

### HTTP Handlers (httptest)

API handler tests use `net/http/httptest` with chi router for URL parameters. Auth middleware is bypassed by injecting the principal directly via `context.WithValue`.

### Kubernetes Types

Controller and collector tests use K8s types directly (e.g., `corev1.Node`) without requiring a running cluster.

## Testing Patterns

- **Table-driven tests** with `t.Run` subtests for parameterized coverage
- **`t.Context()`** (Go 1.24+) for test contexts instead of `context.Background()`
- **`t.Setenv()`** for isolated environment variable testing
- **Direct assertions** using `t.Fatal`/`t.Error` (no assertion libraries)
- **Whitebox testing** (test files in same package for internal access)
- **`wg.Go()`** (Go 1.25+) for concurrent buffer tests
- **`miniredis.RunT(t)`** for Redis-backed tests (auto cleanup)

## Running Specific Tests

```bash
# Single package
go test ./internal/metricsource/expression/...

# Single test function
go test ./internal/metricsource/expression/ -run TestEval_BinaryDiv_ByZero -v

# Pattern match
go test ./internal/rbac/ -run TestMatchSpec -v

# All metricsource packages
go test ./internal/metricsource/...

# Store layer tests
go test ./internal/store/...

# API handler tests
go test ./internal/api/...
```

## Adding New Tests

1. Create `*_test.go` in the same package (whitebox)
2. Use table-driven tests with `t.Run` for multiple cases
3. Use `t.Fatal` for setup failures, `t.Error` for assertion failures
4. Run `go test -race` to verify thread safety
5. For Redis-dependent tests, use `miniredis.RunT(t)` — no real Redis needed
6. For HTTP handler tests, use `httptest.NewRecorder()` + `httptest.NewRequest()`

## Continuous Integration

All tests run automatically on every pull request targeting `main` via GitHub Actions (`.github/workflows/linting.yml`).

### CI Jobs

| Job | What it does |
|-----|-------------|
| **Lint** | Runs `golangci-lint` with the project's `.golangci.yml` config |
| **Test** | Runs `go test -race -coverprofile=coverage.out ./...` |
| **Build** | Compiles all binaries (`cmd/api`, `cmd/collector`, `cmd/manager`) |

All three jobs must pass before a PR can be merged. Results are posted as a sticky comment on the PR with test counts and coverage percentage.

### Running CI Checks Locally

```bash
# Run tests (same as CI)
make test

# Run linter (requires golangci-lint v2.1+)
make lint

# Verify build
make build
```

### Linter Configuration

The project uses `golangci-lint` v2 with the `standard` preset. Configuration is in `.golangci.yml` at the project root. Generated code (`zz_generated.deepcopy.go`, protobuf files) is excluded automatically.
