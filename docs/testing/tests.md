# Go Test Suite

## Overview

The Go test suite covers the core operator services: expression engine, aggregation, field extraction, metric source compilation, RBAC types, API handlers, collector buffer, config loading, and utility parsing. Tests use standard library `testing` only (no testify/gomock).

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

| Package | File | Tests | What It Covers |
|---------|------|-------|----------------|
| `pkg/utils` | `parser_test.go` | 41 | CPU/memory string parsing |
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
| `internal/api` | `handlers_test.go` | 5 | HealthHandler + writeJSON |
| `internal/rbac` | `types_test.go` | 20 | Principal/Resource/Request cache keys, MatchSpec, RBACDecision, CustomResourceDecision |
| `internal/rbac` | `engine_test.go` | 19 | RBAC engine security (existing) |

## Testing Patterns

- **Table-driven tests** with `t.Run` subtests for parameterized coverage
- **`t.Context()`** (Go 1.24+) for test contexts instead of `context.Background()`
- **`t.Setenv()`** for isolated environment variable testing
- **Direct assertions** using `t.Fatal`/`t.Error` (no assertion libraries)
- **Whitebox testing** (test files in same package for internal access)
- **`wg.Go()`** (Go 1.25+) for concurrent buffer tests

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
```

## Adding New Tests

1. Create `*_test.go` in the same package (whitebox)
2. Use table-driven tests with `t.Run` for multiple cases
3. Use `t.Fatal` for setup failures, `t.Error` for assertion failures
4. Run `go test -race` to verify thread safety
5. Avoid external dependencies (no testify, no mocks)
