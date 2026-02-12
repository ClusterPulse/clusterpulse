# Connecting to an External Redis Instance

This document covers the configuration required to use an external Redis instance with ClusterPulse instead of the bundled Bitnami Redis subchart.

## Overview

ClusterPulse uses Redis as a shared data store and cache layer across three components:

- `api` - REST API server
- `clusterEngine` - Cluster connection reconciler
- `policyEngine` - MonitorAccessPolicy reconciler (runs within the cluster-controller binary)

Each component independently reads Redis connection parameters from its respective values block. When using an external Redis, you must configure all three components and disable the built-in Redis subchart.

## Prerequisites

- External Redis instance accessible from the cluster (Redis 6.x+ recommended)
- Network connectivity from the ClusterPulse namespace to the Redis endpoint
- Redis authentication credentials

## Configuration

### Step 1: Create the Redis Password Secret

Create a Kubernetes secret containing the Redis password in the target namespace:

```bash
kubectl create secret generic external-redis-secret \
  --namespace clusterpulse \
  --from-literal=password='<your-redis-password>'
```

Alternatively, use a sealed secret or external secrets operator as per your cluster's secrets management approach.

### Step 2: Configure ClusterPulse CR

Modify the ClusterPulse instance CR to include these values:

```yaml
# Disable the bundled Redis subchart
redis:
  enabled: false

# API component Redis configuration
api:
  redis:
    host: "redis.example.com"
    port: "6379"
    db: "0"
    passwordSecret: "external-redis-secret"
    passwordKey: "password"

# Cluster controller Redis configuration
clusterEngine:
  redis:
    host: "redis.example.com"
    port: "6379"
    db: "0"
    passwordSecret: "external-redis-secret"
    passwordKey: "password"

# Policy controller Redis configuration
policyEngine:
  redis:
    host: "redis.example.com"
    port: "6379"
    db: "0"
    passwordSecret: "external-redis-secret"
    passwordKey: "password"
```

## Configuration Reference

| Parameter | Description | Default |
|-----------|-------------|---------|
| `redis.enabled` | Deploy bundled Redis subchart | `true` |
| `<component>.redis.host` | Redis hostname or IP | `<release>-redis-master` |
| `<component>.redis.port` | Redis port | `6379` |
| `<component>.redis.db` | Redis database index | `0` |
| `<component>.redis.passwordSecret` | Secret name containing password | `<release>-redis` |
| `<component>.redis.passwordKey` | Key within secret for password | `redis-password` |

Where `<component>` is one of: `api`, `clusterEngine`, `policyEngine`.

## Redis Sentinel Configuration

The current Helm chart does not natively support Redis Sentinel connection strings. For HA Redis deployments using Sentinel, consider one of the following approaches:

1. Deploy a Redis proxy (e.g., HAProxy, Envoy) in front of Sentinel and point ClusterPulse to the proxy endpoint.
2. Use a managed Redis service that provides a single stable endpoint (AWS ElastiCache, Azure Cache for Redis, GCP Memorystore).

## Redis Cluster Mode

Redis Cluster (sharded) mode is not supported. ClusterPulse expects a single Redis instance or replica set with a single write endpoint. Please open an issue if required.

## TLS Configuration

TLS connections to Redis are not currently exposed via ClusterPulse CR. If your external Redis required TLS, please open an issue.

## Database Isolation

You can isolate each component to separate Redis databases if required:

```yaml
api:
  redis:
    db: "0"

clusterEngine:
  redis:
    db: "1"

policyEngine:
  redis:
    db: "2"
```

This is generally unnecessary unless debugging or isolating workloads for specific operational reasons. All components expect to share the same Redis database under normal operation.

## Validation

After deployment, verify connectivity from each component:

```bash
# Check API pod logs
kubectl logs -n clusterpulse deployment/clusterpulse-api | grep -i redis

# Check cluster controller logs (includes policy controller)
kubectl logs -n clusterpulse deployment/clusterpulse-cluster-controller | grep -i redis
```

Successful startup logs should indicate a connection to Redis without errors. Failed connections will present as connection refused or authentication errors in the pod logs.
