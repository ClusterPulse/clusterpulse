# Policy Controller for ClusterPulse

## Overview

The Policy Controller is a Kubernetes operator that manages `MonitorAccessPolicy` Custom Resource Definitions (CRDs) for the ClusterPulse monitoring platform. It compiles high-level RBAC policies into optimized data structures and stores them in Redis for high-performance, real-time access control evaluation.
This is by far the smallest portion of ClusterPulse. It will be expanded in the future to a more robust language than Python w/ Kopf.
This is very much a working README w/ plenty to fix.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Policy Format](#policy-format)
- [Installation](#installation)
- [Configuration](#configuration)
- [How It Works](#how-it-works)
- [Monitoring](#monitoring)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)

## Features

- **High-Performance Policy Evaluation**: Compiles policies into optimized structures for sub-millisecond evaluation
- **Multi-Subject Support**: Supports users, groups, and service accounts
- **Resource Filtering**: Fine-grained control over nodes, operators, namespaces, and pods
- **Pattern Matching**: Supports wildcards and regex patterns for resource filtering
- **Priority-Based Resolution**: Handles policy conflicts through priority ordering
- **Lifecycle Management**: Automatic policy expiration and validity periods
- **Real-time Updates**: Immediate policy effect through cache invalidation
- **Audit Support**: Built-in audit logging and access reason requirements
- **Prometheus Metrics**: Comprehensive observability

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Kubernetes API                      │
│                                                       │
│  ┌─────────────────────────────────────────────┐    │
│  │     MonitorAccessPolicy CRDs                 │    │
│  └─────────────────────────────────────────────┘    │
└──────────────────────┬───────────────────────────────┘
                       │ Watch Events
                       ▼
           ┌───────────────────────────┐
           │    Policy Controller      │
           │  ┌──────────────────┐    │
           │  │  Policy Compiler  │    │◄──── Kopf Framework
           │  └──────────────────┘    │
           │  ┌──────────────────┐    │
           │  │  Policy Validator │    │
           │  └──────────────────┘    │
           │  ┌──────────────────┐    │
           │  │   Policy Store    │    │
           │  └──────────────────┘    │
           └───────────┬───────────────┘
                       │
                       ▼
              ┌──────────────────┐
              │      Redis        │
              │                  │
              │ • Compiled Policies
              │ • User Indexes    │
              │ • Group Indexes   │
              │ • Priority Queues │
              │ • Eval Caches     │
              └──────────────────┘
```

### Components

- **Policy Compiler**: Transforms high-level policy specifications into optimized data structures
- **Policy Validator**: Validates policies for correctness, expiration, and lifecycle rules
- **Policy Store**: Manages Redis storage, indexing, and cache invalidation
- **Resource Manager**: Handles graceful shutdown and resource cleanup
- **Batch Processor**: Optimizes Redis operations through pipelining

## Policy Format

Policies use a structured YAML format with five main sections:

```yaml
apiVersion: clusterpulse.io/v1alpha1
kind: MonitorAccessPolicy
metadata:
  name: example-policy
  namespace: clusterpulse
spec:
  identity:
    priority: 100  # Lower values = higher priority
    subjects:
      users:
        - alice@example.com
        - bob@example.com
      groups:
        - platform-team
        - sre-team
      serviceAccounts:
        - name: monitoring-sa
          namespace: monitoring
  
  access:
    effect: Allow  # Allow or Deny
    enabled: true
  
  scope:
    clusters:
      default: none  # Default access level: all, none, or filtered
      rules:
        - selector:
            environment: production
            region: us-west
          permissions:
            view: true
            exec: false
            portForward: false
            logs: true
          resources:
            nodes:
              visibility: filtered
              filters:
                hideMasters: true
                hideByLabels:
                  - node-role.kubernetes.io/control-plane
            operators:
              visibility: filtered
              filters:
                allowedNamespaces:
                  - "operator-*"
                  - monitoring
                deniedNames:
                  - "*-test"
            namespaces:
              visibility: filtered
              filters:
                allowed:
                  - "app-*"
                  - default
                denied:
                  - kube-system
                  - kube-public
            pods:
              visibility: filtered
              filters:
                allowedNamespaces:
                  - "app-*"
    
  lifecycle: # Has not been tested
    validity:
      notBefore: "2024-01-01T00:00:00Z"
      notAfter: "2024-12-31T23:59:59Z"
  
  operations:
    audit:
      logAccess: true
      requireReason: true
```

### Policy Sections

#### Identity Section
- **priority**: Policy evaluation order (0-999, lower = higher priority)
- **subjects**: Who the policy applies to (users, groups, service accounts)

#### Access Section
- **effect**: Whether to Allow or Deny access
- **enabled**: Policy activation state

#### Scope Section
- **clusters**: Cluster-level access rules and resource filters

#### Lifecycle Section
- **validity**: Time-based policy activation with notBefore/notAfter

#### Operations Section
- **audit**: Audit logging configuration

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NAMESPACE` | Namespace to watch for policies | `clusterpulse` |
| `REDIS_HOST` | Redis server hostname | `redis` |
| `REDIS_PORT` | Redis server port | `6379` |
| `REDIS_PASSWORD` | Redis authentication password | None |
| `REDIS_DB` | Redis database number | `0` |
| `POLICY_CACHE_TTL` | Policy cache TTL in seconds | `300` |
| `GROUP_CACHE_TTL` | Group membership cache TTL | `300` |

### Redis Configuration

The controller uses Redis for:
- **Policy Storage**: Compiled policies stored as JSON
- **Indexing**: Multiple indexes for fast lookup by user/group/service account
- **Caching**: Evaluation results cached with TTL
- **Pub/Sub**: Policy change events

Required Redis memory: ~1KB per policy + indexes

## How It Works

### Policy Compilation Process

1. **CRD Event**: Controller receives create/update/delete events via Kopf
2. **Validation**: Policy spec is validated for correctness
3. **Compilation**: High-level spec compiled into optimized structure
4. **Pattern Compilation**: Wildcard patterns converted to regex
5. **Storage**: Compiled policy stored in Redis with multiple indexes
6. **Cache Invalidation**: Affected user/group caches cleared
7. **Event Publication**: Change event published via Redis pub/sub

### Indexing Strategy

The controller maintains several Redis indexes for O(1) policy lookup:

```
policy:{namespace}:{name}           # Main policy storage
policy:user:{username}              # Policies by user
policy:group:{groupname}            # Policies by group  
policy:sa:{serviceaccount}          # Policies by service account
policies:by:priority                # Sorted set by priority
policies:enabled                    # Set of active policies
```

### Cache Invalidation

When policies change, the controller:
1. Identifies affected users, groups, and service accounts
2. Scans for evaluation cache keys using pattern matching
3. Batch deletes cached evaluations
4. Publishes invalidation events

### Pattern Matching

Resource filters support wildcards:
- `*` matches any characters
- `?` matches single character
- Literals are indexed separately for O(1) lookup
- Patterns compiled to regex for evaluation

## Monitoring

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `policy_compilation_duration_seconds` | Histogram | Time to compile policy |
| `policy_cache_operations_total` | Counter | Cache operations count |
| `active_policies_total` | Gauge | Currently active policies |
| `policy_errors_total` | Counter | Policy processing errors |
| `redis_operation_duration_seconds` | Histogram | Redis operation latency |

### Health Probes

```bash
# Liveness probe
curl http://policy-controller:8080/healthz

# Readiness probe (via Kopf)
curl http://policy-controller:8080/healthz
```

### Logging

The controller uses structured logging with levels:
- `INFO`: Normal operations
- `WARNING`: Recoverable issues
- `ERROR`: Failures requiring attention
- `DEBUG`: Detailed troubleshooting

## Development

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally (requires kubeconfig)
export REDIS_HOST=localhost
export NAMESPACE=clusterpulse
python policy_controller.py
```

### Building

```bash
# Build container
docker build -t policy-controller:latest .

# Multi-arch build
docker buildx build --platform linux/amd64,linux/arm64 \
  -t policy-controller:latest .
```

## Troubleshooting

### Common Issues

#### Policy Not Taking Effect
```bash
# Check policy compilation status
kubectl get monitoraccesspolicy -n clusterpulse -o yaml

# Check controller logs
kubectl logs -n clusterpulse deployment/policy-controller

# Verify Redis connectivity
kubectl exec -n clusterpulse deployment/policy-controller -- redis-cli ping
```

#### High Memory Usage
```bash
# Check policy count
redis-cli SCARD policies:all

# Clear evaluation caches
redis-cli --scan --pattern "policy:eval:*" | xargs redis-cli DEL

# Check cache TTLs
redis-cli CONFIG GET "*ttl*"
```

#### Performance Issues
```bash
# Check compilation metrics
curl http://policy-controller:8080/metrics | grep compilation

# Monitor Redis latency
redis-cli --latency

# Check batch processing
kubectl logs -n clusterpulse deployment/policy-controller | grep batch
```

### Debug Commands

```bash
# List all policies in Redis
redis-cli SMEMBERS policies:all

# Get specific policy
redis-cli HGETALL policy:clusterpulse:example-policy

# Check user policies
redis-cli SMEMBERS policy:user:alice@example.com

# Monitor policy events
redis-cli SUBSCRIBE policy-events
```

## API Reference

### CRD Schema

See the operator configuration for CRD definitions.

### Redis Keys

| Key Pattern | Type | Description |
|-------------|------|-------------|
| `policy:{ns}:{name}` | Hash | Compiled policy data |
| `policy:user:{user}` | Set | Policy keys for user |
| `policy:group:{group}` | Set | Policy keys for group |
| `policy:eval:{identity}:{cluster}` | String | Cached evaluation |
| `user:groups:{username}` | Set | User's group memberships |

### Events

The controller publishes events to Redis channels:
- `policy-changes`: Policy CRUD events
- `policy-events`: Typed events for consumers
