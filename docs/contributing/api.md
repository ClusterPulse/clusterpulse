# Contributing to ClusterPulse API

## Getting Started

### Local Setup

```bash
# Start Redis
docker run -d -p 6379:6379 redis:latest

# Build the API
go build -o bin/api ./cmd/api/

# Run in development mode (no OAuth required)
ENVIRONMENT=development OAUTH_PROXY_ENABLED=false REDIS_HOST=localhost ./bin/api
```

API health check at `http://localhost:8080/healthz`

### Swagger UI

Interactive API documentation is served at `/api/v1/swagger/index.html`. It is **disabled by default** and must be explicitly enabled via the `SWAGGER_ENABLED` env var:

```bash
SWAGGER_ENABLED=true ENVIRONMENT=development OAUTH_PROXY_ENABLED=false REDIS_HOST=localhost ./bin/api
```

No authentication is required to access the Swagger UI.

By default, the Swagger UI "Try it out" feature uses the browser's current URL as the API base (works automatically behind reverse proxies). To override, set `SWAGGER_HOST`:

```bash
SWAGGER_HOST=my-cluster.example.com SWAGGER_ENABLED=true ./bin/api
```

#### Regenerating Swagger Docs

After modifying handler annotations (the `// @` comment blocks above handler functions), regenerate the docs:

```bash
# Install swag CLI (one-time)
go install github.com/swaggo/swag/cmd/swag@latest

# Regenerate docs/swagger/
swag init -g cmd/api/main.go -o docs/swagger --parseDependency --parseInternal
```

The generated files in `docs/swagger/` (docs.go, swagger.json, swagger.yaml) are committed to the repo. Always regenerate and commit after changing annotations.

### Project Structure

```
cmd/api/main.go                   # Entrypoint
internal/rbac/
    types.go                      # RBAC types (Action, ResourceType, Filter, etc.)
    engine.go                     # Core RBAC engine (authorize, filter)
    filter.go                     # Filter compilation and matching helpers
    cache.go                      # Decision cache (Redis-backed)
  metrics.go                      # FilteredMetricsCalculator
internal/api/
  config.go                       # API configuration (env vars)
  server.go                       # Chi router + middleware + graceful shutdown
  middleware.go                   # Auth + optional auth middleware + security headers
  handlers.go                     # Health endpoints
  clusters.go                     # Cluster route handlers
  auth.go                         # Auth introspection handlers (status, me, permissions, policies, logout, cache)
  registries.go                   # Registry status handler
  custom_types.go                 # Custom resource type discovery handlers
  aggregations.go                 # Aggregation recomputation utility
internal/store/
  reader.go                       # Redis read operations for API
  client.go                       # Shared Redis client (+ RedisClient() accessor)
```

### Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `API_PORT` | 8080 | Server port |
| `API_HOST` | 0.0.0.0 | Bind address |
| `CORS_ORIGINS` | * | Allowed CORS origins |
| `OAUTH_PROXY_ENABLED` | true | Enable OAuth proxy headers |
| `OAUTH_HEADER_USER` | X-Forwarded-User | Username header |
| `OAUTH_HEADER_EMAIL` | X-Forwarded-Email | Email header |
| `ENVIRONMENT` | production | development/production |
| `RBAC_CACHE_TTL` | 0 | Cache TTL seconds (0=disabled) |
| `SWAGGER_ENABLED` | false | Enable Swagger UI at `/api/v1/swagger/` |
| `SWAGGER_HOST` | _(empty)_ | Override Swagger API host (empty = use browser URL) |

### API Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/healthz` | None | Health check |
| GET | `/readyz` | None | Readiness (pings Redis) |
| GET | `/api/v1/swagger/*` | None | Swagger UI (requires `SWAGGER_ENABLED=true`) |
| GET | `/api/v1/auth/status` | Optional | Authentication status |
| GET | `/api/v1/auth/me` | Required | Current user info with groups |
| GET | `/api/v1/auth/permissions` | Required | Per-cluster permission summary |
| GET | `/api/v1/auth/policies` | Required | Applied policies sorted by priority |
| POST | `/api/v1/auth/logout` | Required | Clear RBAC + group + permission caches |
| POST | `/api/v1/auth/cache/clear` | Required | Clear RBAC cache for current user |
| GET | `/api/v1/registries/status` | Required | Registry availability (pipelined) |
| GET | `/api/v1/clusters` | Required | List accessible clusters |
| GET | `/api/v1/clusters/{name}` | Required | Cluster detail |
| GET | `/api/v1/clusters/{name}/nodes` | Required | Cluster nodes |
| GET | `/api/v1/clusters/{name}/nodes/{node}` | Required | Node detail |
| GET | `/api/v1/clusters/{name}/operators` | Required | Cluster operators |
| GET | `/api/v1/clusters/{name}/namespaces` | Required | Cluster namespaces |
| GET | `/api/v1/clusters/{name}/alerts` | Required | Cluster alerts |
| GET | `/api/v1/clusters/{name}/events` | Required | Cluster events |
| GET | `/api/v1/clusters/{name}/custom/{type}` | Required | Custom resources |
| GET | `/api/v1/custom-types` | Required | Accessible custom resource types |
| GET | `/api/v1/custom-types/clusters` | Required | Resource counts per type per cluster |

### Go API Response Format

The Go API returns raw CRD blobs (`spec`, `status`, `info`, `metrics`) directly instead of flattening individual fields. This keeps the API layer thin and lets the UI read from structured objects.

**`GET /api/v1/clusters`** — each item:
```json
{
  "name": "prod-east",
  "accessible": true,
  "spec": { "displayName": "Production East", "labels": { "environment": "production" } },
  "info": { "version": "4.14.8", "channel": "stable-4.14", "console_url": "https://...", "api_url": "https://...", "platform": "AWS" },
  "metrics": { "nodes": 6, "nodes_ready": 6, "namespaces": 42, "pods": 310, "pods_running": 295 },
  "status": { "health": "healthy", "last_check": "2025-01-15T10:30:00Z" },
  "operator_count": 12
}
```

**`GET /api/v1/clusters/{name}`** — same blobs plus `resource_collection` and `operator_count`.

**`GET /api/v1/registries/status`** — each item:
```json
{
  "name": "quay-prod",
  "spec": { "displayName": "Quay Production", "endpoint": "https://quay.example.com" },
  "status": { "available": true, "responseTime": 42 }
}
```
