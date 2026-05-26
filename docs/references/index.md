# References

## CRDs

The CRD reference is generated from the Go type definitions in [`api/v1alpha1/`](https://github.com/ClusterPulse/clusterpulse/tree/main/api/v1alpha1) using [`crd-ref-docs`](https://github.com/elastic/crd-ref-docs).

CRDs defined in this repo:

| Kind | Short names | Purpose |
|---|---|---|
| `ClusterConnection` | `cc` | Registers a Kubernetes/OpenShift cluster as a monitoring target. |
| `RegistryConnection` | `rc`, `regcon` | Registers a container registry for health monitoring. |
| `MetricSource` | `ms`, `metricsrc` | Defines a custom-resource collection template (what to collect, how to extract fields, how to aggregate). |
| `MonitorAccessPolicy` | `map`, `policy` | RBAC policy controlling who can see what. |

The Go source is the authoritative spec:

- [`api/v1alpha1/clusterconnection_types.go`](https://github.com/ClusterPulse/clusterpulse/blob/main/api/v1alpha1/clusterconnection_types.go)
- [`api/v1alpha1/registryconnection_types.go`](https://github.com/ClusterPulse/clusterpulse/blob/main/api/v1alpha1/registryconnection_types.go)
- [`api/v1alpha1/metricsource_types.go`](https://github.com/ClusterPulse/clusterpulse/blob/main/api/v1alpha1/metricsource_types.go)
- [`api/v1alpha1/monitoraccesspolicy_types.go`](https://github.com/ClusterPulse/clusterpulse/blob/main/api/v1alpha1/monitoraccesspolicy_types.go)

Generated CRD YAML lives under `config/crd/bases/` in the repo and is what the operator chart ships.

## REST API (Swagger)

The REST API is annotated with `swaggo` comments and the rendered docs are served at `/api/v1/swagger/index.html` when `SWAGGER_ENABLED=true` is set on the API pod. See [Contributing → API → Swagger UI](../contributing/api.md#swagger-ui) for how to enable it locally and regenerate the generated files in `docs/swagger/`.

The route table is in [Contributing → API → API routes](../contributing/api.md#api-routes).

## Generating the docs

To regenerate the CRD reference page:

```bash
# Install crd-ref-docs
go install github.com/elastic/crd-ref-docs@latest

# Render to docs/references/crds.md
crd-ref-docs \
    --source-path=./api/v1alpha1 \
    --config=./docs/crd-ref-docs.yaml \
    --renderer=markdown \
    --output-path=./docs/references/crds.md
```

The `crd-ref-docs.yaml` config controls which types are ignored and which K8s types are linked to upstream docs.
