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

## 🏗️ Architecture

![architecture](/screenshots/architecture.jpg)

ClusterPulse follows a microservices architecture with four core components:

### Components Overview

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Cluster Controller** | Go | Connects to target clusters, collects metrics, and stores in Redis |
| **Policy Controller** | Python, Kopf | Compiles RBAC policies into optimized structures for real-time evaluation |
| **API** | Python, FastAPI | Serves filtered cluster data based on user permissions |
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

The usual method of deployment is through OLM. Currently working on deploying to OperatorHub.

### Helm
```
git clone https://github.com/ClusterPulse/operator.git
cd operator/
make install							# Will install CRDs
helm install clusterpulse ./helm-charts/clusterpulse		# Will install ClusterPulse
```

## 📚 Documentation

Detailed documentation for each component:

- [API Documentation](./api/README.md) - Backend API service and RBAC engine
- [Frontend Documentation](./frontend/README.md) - React dashboard and UI components
- [Cluster Controller Documentation](./cluster-controller/README.md) - Cluster connection manager
- [Policy Engine Documentation](./policy-engine/README.md) - Policy compilation and management

### Technology Stack

- **Backend**: Python (FastAPI)
- **Controllers**: Python (Kopf), Go
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
