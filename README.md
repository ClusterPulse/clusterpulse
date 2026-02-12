# ClusterPulse

**Enterprise Multi-Cluster Kubernetes Monitoring with Fine-Grained Access Control**

ClusterPulse is a comprehensive monitoring platform designed for organizations managing multiple Kubernetes and OpenShift clusters. It provides real-time visibility into cluster health, resource utilization, and operational status while enforcing granular Role-Based Access Control (RBAC) to ensure teams only see what they need to see.

## 🎯 Why ClusterPulse?

### The Challenge
Organizations operating multiple Kubernetes clusters face several critical challenges:
- **Visibility Gaps**: No unified view across all clusters, leading to blind spots in infrastructure monitoring
- **Security Concerns**: Difficulty implementing fine-grained access control across multiple clusters
- **Operational Overhead**: Teams waste time switching between different tools and contexts
- **Compliance Requirements**: Need to restrict data access based on roles, teams, and regulatory requirements
- **Resource Inefficiency**: Inability to spot underutilized resources across the fleet

### The ClusterPulse Solution
ClusterPulse addresses these challenges by providing:

- **📊 Unified Multi-Cluster Dashboard**: Monitor all your clusters from a single pane of glass with real-time metrics and health status
- **🔒 Enterprise-Grade RBAC**: Define sophisticated access policies that filter visibility down to the namespace, node, and pod level
- **⚡ Real-Time Performance**: Sub-second response times (cluster size dependent) with intelligent caching and optimized data structures
- **🔄 Automatic Discovery**: Automatically discovers and monitors nodes, operators, namespaces, and resources
- **📈 Scalable Architecture**: Designed to handle hundreds of clusters with thousands of nodes

## 📄 Documentation
ClusterPulse documentation is deployed via mkdocs. See more [here](https://clusterpulse.github.io/clusterpulse/latest/)

## 🏗️ Architecture

![architecture](/docs/assets/architecture.jpg)

ClusterPulse follows a microservices architecture with four core components:

### Components Overview

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Cluster Controller** | Go | Connects to target clusters, collects metrics, and stores in Redis |
| **Policy Controller** | Go | Compiles RBAC policies into optimized structures (runs within cluster-controller) |
| **API** | Go, Chi | Serves filtered cluster data based on user permissions |
| **Frontend** | React, TypeScript, PatternFly | Provides intuitive dashboard for cluster monitoring |

### Data Flow
1. **Cluster Controller** connects to configured clusters and continuously collects metrics
2. **Policy Engine** watches for policy changes and compiles them for fast evaluation
3. **API** combines cluster data with policies to serve filtered, authorized responses
4. **Frontend** displays real-time, personalized views based on user permissions

## ✨ Key Features

### Multi-Cluster Management
- Monitor unlimited OpenShift clusters
- Automatic detection of cluster version and platform
- Real-time health status with color-coded indicators

### Fine-Grained RBAC
- **Subject-Based Policies**: Define access for users, groups, and service accounts
- **Resource Filtering**: Control visibility of nodes, operators, namespaces, and pods
- **Pattern Matching**: Use wildcards and regex for flexible resource selection
- **Priority Resolution**: Handle policy conflicts with priority-based ordering

### Real-Time Monitoring
- **X-Second Auto-Refresh**: Modifiable reconciliation timer
- **Resource Metrics**: CPU, memory, storage utilization
- **Node Health**: Track node status, conditions, and resource pressure
- **Operator Status**: Monitor OLM-managed operators across namespaces
- **Registry Health**: Track container registry availability

### Enterprise Features
- **OAuth2 Integration**: Seamless authentication with enterprise identity providers
- **Dark Mode Support**: Reduce eye strain with theme preferences
- **Responsive Design**: Access from desktop, tablet, or mobile devices
- **Prometheus Metrics**: Export metrics for integration with existing monitoring
- **High Availability**: Redis-backed storage with clustering support

## Deployment

### OperatorHub
ClusterPulse can be deployed through OLM in the OperatorHub. It is currently inside the community operator index!

### Helm
```
git clone https://github.com/ClusterPulse/operator.git
cd operator/
make install							# Will install CRDs
helm install clusterpulse ./helm-charts/clusterpulse		# Will install ClusterPulse
```

## 📚 Documentation

Detailed documentation for each component:

- [Full Documentation](https://clusterpulse.github.io/clusterpulse/latest/) - Hosted docs site
- [API Contributing Guide](./docs/contributing/api.md) - Go API server and RBAC engine
- [Cluster Controller Guide](./docs/contributing/cluster-controller.md) - Cluster connection manager
- [Policy Controller Guide](./docs/contributing/policy-controller.md) - Policy compilation and management

### Technology Stack

- **Backend**: Go (Chi)
- **Controllers**: Go (controller-runtime)
- **Frontend**: React, TypeScript
- **Storage**: Redis
- **Container**: Kubernetes/OpenShift
- **Protocols**: REST API, WebSocket (future)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details. - TBD

### Areas for Contribution
- Additional cluster platform support
- Enhanced visualizations and charts
- Performance optimizations
- Documentation improvements
- Testing and quality assurance - (I've been bad about unit tests sorry >\_<)

## 📄 License

ClusterPulse is released under the [Apache 2.0 License](LICENSE).

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/ClusterPulse/clusterpulse/issues)

---

**ClusterPulse** - Bringing clarity to multi-cluster Kubernetes operations.
