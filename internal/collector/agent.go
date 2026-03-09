package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"strings"

	mscollector "github.com/clusterpulse/cluster-controller/internal/metricsource/collector"
	"github.com/clusterpulse/cluster-controller/internal/version"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/clusterpulse/cluster-controller/pkg/utils"
	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Agent is the collector agent that runs on managed clusters.
// It collects metrics locally and pushes them to the hub ingester via gRPC.
type Agent struct {
	config  *Config
	collect *mscollector.Collector

	// K8s clients for in-cluster collection
	dynamicClient dynamic.Interface
	clientset     kubernetes.Interface

	// gRPC connection
	conn   *grpc.ClientConn
	stream pb.CollectorService_ConnectClient

	// MetricSource configs received from ingester
	mu      sync.RWMutex
	sources []*types.CompiledMetricSource

	// Local buffer for network outages
	buffer *Buffer

	startTime          time.Time
	lastOperatorCollect time.Time
	lastInfoCollect     time.Time
}

// NewAgent creates a new collector agent.
func NewAgent(cfg *Config, dynamicClient dynamic.Interface, clientset kubernetes.Interface) *Agent {
	return &Agent{
		config:        cfg,
		collect:       mscollector.NewCollector(),
		dynamicClient: dynamicClient,
		clientset:     clientset,
		buffer:        NewBuffer(cfg.BufferSize),
		startTime:     time.Now(),
	}
}

// Run starts the agent's main loop. It connects to the ingester, registers,
// then runs collect-push cycles until the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	log := logrus.WithField("component", "collector-agent")

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := a.connectAndRun(ctx); err != nil {
			log.WithError(err).Warn("Connection lost, reconnecting...")
		}

		// Exponential backoff on reconnect
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(a.config.ReconnectBackoff()):
		}
	}
}

func (a *Agent) connectAndRun(ctx context.Context) error {
	log := logrus.WithField("component", "collector-agent")

	// Build transport credentials
	var transportCreds credentials.TransportCredentials
	if a.config.TLSEnabled {
		var pool *x509.CertPool
		if a.config.TLSCACert != "" {
			caCert, err := os.ReadFile(a.config.TLSCACert)
			if err != nil {
				return fmt.Errorf("failed to read CA cert %s: %w", a.config.TLSCACert, err)
			}
			pool = x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to parse CA cert from %s", a.config.TLSCACert)
			}
			log.WithField("ca", a.config.TLSCACert).Info("Using custom CA certificate")
		} else {
			var err error
			pool, err = x509.SystemCertPool()
			if err != nil {
				return fmt.Errorf("failed to load system CA pool: %w", err)
			}
			log.Info("Using system CA trust store")
		}
		tlsCfg := &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		}
		// When TLSServerName is set, the dial address (route hostname) differs from
		// the certificate SANs (in-cluster service name). We verify the cert chain
		// against the in-cluster name via VerifyConnection while keeping the route
		// hostname as SNI for passthrough routing. This is the same pattern used by
		// Kubernetes client-go for custom server name verification.
		if a.config.TLSServerName != "" {
			log.WithField("serverName", a.config.TLSServerName).Info("Using custom TLS server name for certificate verification")
			verifyPool := pool
			tlsCfg.InsecureSkipVerify = true
			tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
				opts := x509.VerifyOptions{
					DNSName: a.config.TLSServerName,
					Roots:   verifyPool,
				}
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("no peer certificates presented")
				}
				if len(cs.PeerCertificates) > 1 {
					opts.Intermediates = x509.NewCertPool()
					for _, cert := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(cert)
					}
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			}
		}
		transportCreds = credentials.NewTLS(tlsCfg)
	} else {
		transportCreds = insecure.NewCredentials()
	}

	// Connect to ingester
	conn, err := grpc.NewClient(
		a.config.IngesterAddress,
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer func() { _ = conn.Close() }()
	a.conn = conn

	// Create stream with auth metadata
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + a.config.Token,
	})
	streamCtx := metadata.NewOutgoingContext(ctx, md)

	client := pb.NewCollectorServiceClient(conn)
	stream, err := client.Connect(streamCtx)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	a.stream = stream

	// Register
	if err := stream.Send(&pb.ConnectRequest{
		Payload: &pb.ConnectRequest_Register{
			Register: &pb.RegisterRequest{
				ClusterName: a.config.ClusterName,
				Token:       a.config.Token,
				Version:     version.Version,
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	log.WithField("cluster", a.config.ClusterName).Info("Registered with ingester")
	a.config.ResetBackoff()

	// Start receiving messages in background
	recvDone := make(chan error, 1)
	go func() {
		recvDone <- a.receiveLoop(ctx, stream)
	}()

	// Flush any buffered batches first
	a.flushBuffer(ctx, stream)

	// Collection loop
	ticker := time.NewTicker(time.Duration(a.config.CollectIntervalSeconds) * time.Second)
	defer ticker.Stop()

	// Heartbeat ticker
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-recvDone:
			return fmt.Errorf("receive loop ended: %w", err)

		case <-ticker.C:
			batch, err := a.collectMetrics(ctx)
			if err != nil {
				log.WithError(err).Warn("Collection failed")
				continue
			}

			if err := stream.Send(&pb.ConnectRequest{
				Payload: &pb.ConnectRequest_Metrics{Metrics: batch},
			}); err != nil {
				// Buffer the batch for retry
				a.buffer.Push(batch)
				return fmt.Errorf("failed to send metrics: %w", err)
			}

			log.WithFields(logrus.Fields{
				"batch_id":         batch.BatchId,
				"custom_resources": len(batch.CustomResources),
			}).Debug("Pushed metrics batch")

		case <-heartbeat.C:
			if err := stream.Send(&pb.ConnectRequest{
				Payload: &pb.ConnectRequest_Health{
					Health: &pb.HealthReport{
						ClusterName:     a.config.ClusterName,
						Timestamp:       timestamppb.Now(),
						UptimeSeconds:   int64(time.Since(a.startTime).Seconds()),
						BufferedBatches: int32(a.buffer.Len()),
					},
				},
			}); err != nil {
				return fmt.Errorf("failed to send heartbeat: %w", err)
			}
		}
	}
}

func (a *Agent) receiveLoop(ctx context.Context, stream pb.CollectorService_ConnectClient) error {
	log := logrus.WithField("component", "collector-agent")

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return fmt.Errorf("stream closed by server")
		}
		if err != nil {
			return err
		}

		switch payload := msg.Payload.(type) {
		case *pb.ConnectResponse_Config:
			a.applyConfig(payload.Config)
			log.Infof("Received config update: %d metric sources", len(payload.Config.MetricSourcesJson))

		case *pb.ConnectResponse_Ack:
			if !payload.Ack.Success {
				log.WithField("batch_id", payload.Ack.BatchId).
					Warnf("Batch rejected: %s", payload.Ack.Error)
			}
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (a *Agent) applyConfig(update *pb.ConfigUpdate) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.sources = nil
	for _, data := range update.MetricSourcesJson {
		var src types.CompiledMetricSource
		if err := json.Unmarshal(data, &src); err != nil {
			logrus.WithError(err).Warn("Failed to unmarshal metric source config")
			continue
		}
		// Rebuild runtime fields
		src.FieldNameToIndex = make(map[string]int)
		for i, f := range src.Fields {
			src.FieldNameToIndex[f.Name] = i
		}
		a.sources = append(a.sources, &src)
	}

	if update.DefaultIntervalSeconds > 0 {
		a.config.CollectIntervalSeconds = int(update.DefaultIntervalSeconds)
	}
}

func (a *Agent) collectMetrics(ctx context.Context) (*pb.MetricsBatch, error) {
	batch := &pb.MetricsBatch{
		ClusterName: a.config.ClusterName,
		BatchId:     uuid.New().String(),
		CollectedAt: timestamppb.Now(),
	}

	// Collect cluster and node metrics
	clusterMetrics, nodeMetrics, err := a.collectClusterAndNodeMetrics(ctx)
	if err != nil {
		logrus.WithError(err).Warn("Failed to collect cluster/node metrics")
	} else {
		batch.ClusterMetrics = clusterMetrics
		batch.NodeMetrics = nodeMetrics
	}

	// Collect operators and cluster info at a reduced frequency
	scanInterval := time.Duration(a.config.OperatorScanInterval) * time.Second
	if time.Since(a.lastOperatorCollect) >= scanInterval {
		batch.Operators = a.collectOperators(ctx)
		batch.ClusterOperators = a.collectClusterOperators(ctx)
		a.lastOperatorCollect = time.Now()
	}
	if time.Since(a.lastInfoCollect) >= scanInterval {
		batch.ClusterInfo = a.collectClusterInfo(ctx)
		a.lastInfoCollect = time.Now()
	}

	// Collect custom resources from MetricSources
	a.mu.RLock()
	sources := a.sources
	a.mu.RUnlock()

	for _, src := range sources {
		result, err := a.collect.Collect(ctx, a.dynamicClient, src, a.config.ClusterName)
		if err != nil {
			logrus.WithError(err).Debugf("Failed to collect %s/%s", src.Namespace, src.Name)
			continue
		}

		crBatch := &pb.CustomResourceBatch{
			SourceId:      src.Namespace + "/" + src.Name,
			ResourceCount: int32(result.Collection.ResourceCount),
			Truncated:     result.Collection.Truncated,
			DurationMs:    result.Collection.DurationMs,
		}

		for _, r := range result.Collection.Resources {
			valuesJSON, _ := json.Marshal(r.Values)
			crBatch.Resources = append(crBatch.Resources, &pb.CustomCollectedResource{
				Id:         r.ID,
				Namespace:  r.Namespace,
				Name:       r.Name,
				Labels:     r.Labels,
				ValuesJson: valuesJSON,
			})
		}

		if result.Aggregations != nil {
			crBatch.AggregationValues = make(map[string]float64)
			for k, v := range result.Aggregations.Values {
				if f, ok := toFloat64(v); ok {
					crBatch.AggregationValues[k] = f
				}
			}
		}

		batch.CustomResources = append(batch.CustomResources, crBatch)
	}

	return batch, nil
}

func (a *Agent) collectClusterAndNodeMetrics(ctx context.Context) (*pb.ClusterMetrics, []*pb.NodeMetrics, error) {
	nodes, err := a.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	pods, err := a.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Group pods by node
	podsByNode := make(map[string][]corev1.Pod)
	for _, pod := range pods.Items {
		if pod.Spec.NodeName != "" {
			podsByNode[pod.Spec.NodeName] = append(podsByNode[pod.Spec.NodeName], pod)
		}
	}

	cm := &pb.ClusterMetrics{}
	var pbNodes []*pb.NodeMetrics

	for _, node := range nodes.Items {
		nm := a.extractNodeMetrics(&node, podsByNode[node.Name])
		pbNodes = append(pbNodes, nm)

		// Aggregate into cluster metrics
		if nm.Status == string(types.NodeReady) {
			cm.NodesReady++
		}
		cm.CpuCapacity += nm.CpuCapacity
		cm.MemoryCapacity += nm.MemoryCapacity
		cm.Pods += nm.PodsTotal
		cm.PodsRunning += nm.PodsRunning
	}

	cm.Nodes = int32(len(nodes.Items))

	// Namespaces
	namespaces, err := a.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.WithError(err).Debug("Failed to list namespaces")
	} else {
		cm.Namespaces = int32(len(namespaces.Items))
		for _, ns := range namespaces.Items {
			cm.NamespaceList = append(cm.NamespaceList, ns.Name)
		}
	}

	// Workload counts
	if deps, err := a.clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{}); err == nil {
		cm.Deployments = int32(len(deps.Items))
	}

	return cm, pbNodes, nil
}

func (a *Agent) extractNodeMetrics(node *corev1.Node, pods []corev1.Pod) *pb.NodeMetrics {
	nm := &pb.NodeMetrics{
		Name:   node.Name,
		Labels: node.Labels,
	}

	// Roles
	for label := range node.Labels {
		if role, ok := strings.CutPrefix(label, "node-role.kubernetes.io/"); ok {
			nm.Roles = append(nm.Roles, role)
		}
	}

	// Status from conditions
	nm.Status = string(types.NodeUnknown)
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			if condition.Status == corev1.ConditionTrue {
				nm.Status = string(types.NodeReady)
			} else {
				nm.Status = string(types.NodeNotReady)
			}
		}
	}
	if node.Spec.Unschedulable {
		nm.Status = string(types.NodeSchedulingDisabled)
	}

	// Capacity & allocatable
	nm.CpuCapacity = utils.ParseCPU(node.Status.Capacity.Cpu().String())
	nm.MemoryCapacity = utils.ParseMemory(node.Status.Capacity.Memory().String())
	nm.StorageCapacity = utils.ParseMemory(node.Status.Capacity.StorageEphemeral().String())
	nm.PodsCapacity = int32(node.Status.Capacity.Pods().Value())
	nm.CpuAllocatable = utils.ParseCPU(node.Status.Allocatable.Cpu().String())
	nm.MemoryAllocatable = utils.ParseMemory(node.Status.Allocatable.Memory().String())
	nm.StorageAllocatable = utils.ParseMemory(node.Status.Allocatable.StorageEphemeral().String())
	nm.PodsAllocatable = int32(node.Status.Allocatable.Pods().Value())

	// Pod counts and resource requests
	var cpuRequested float64
	var memoryRequested int64
	podsByPhase := make(map[corev1.PodPhase]int32)
	for _, pod := range pods {
		podsByPhase[pod.Status.Phase]++
		if pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending {
			for _, container := range pod.Spec.Containers {
				if container.Resources.Requests != nil {
					cpuRequested += utils.ParseCPU(container.Resources.Requests.Cpu().String())
					memoryRequested += utils.ParseMemory(container.Resources.Requests.Memory().String())
				}
			}
		}
	}
	nm.CpuRequested = cpuRequested
	nm.MemoryRequested = memoryRequested
	nm.PodsRunning = podsByPhase[corev1.PodRunning]
	nm.PodsPending = podsByPhase[corev1.PodPending]
	nm.PodsFailed = podsByPhase[corev1.PodFailed]
	nm.PodsSucceeded = podsByPhase[corev1.PodSucceeded]
	nm.PodsTotal = int32(len(pods))

	if nm.CpuAllocatable > 0 {
		nm.CpuUsagePercent = (cpuRequested / nm.CpuAllocatable) * 100
	}
	if nm.MemoryAllocatable > 0 {
		nm.MemoryUsagePercent = float64(memoryRequested) / float64(nm.MemoryAllocatable) * 100
	}

	// System info
	nm.KernelVersion = node.Status.NodeInfo.KernelVersion
	nm.OsImage = node.Status.NodeInfo.OSImage
	nm.ContainerRuntime = node.Status.NodeInfo.ContainerRuntimeVersion
	nm.KubeletVersion = node.Status.NodeInfo.KubeletVersion
	nm.Architecture = node.Status.NodeInfo.Architecture

	// Network
	for _, addr := range node.Status.Addresses {
		switch addr.Type {
		case corev1.NodeInternalIP:
			nm.InternalIp = addr.Address
		case corev1.NodeHostName:
			nm.Hostname = addr.Address
		}
	}

	return nm
}

// collectOperators queries OLM Subscriptions + CSVs and returns proto OperatorInfo.
func (a *Agent) collectOperators(ctx context.Context) []*pb.OperatorInfo {
	subscriptionGVR := schema.GroupVersionResource{
		Group: "operators.coreos.com", Version: "v1alpha1", Resource: "subscriptions",
	}
	csvGVR := schema.GroupVersionResource{
		Group: "operators.coreos.com", Version: "v1alpha1", Resource: "clusterserviceversions",
	}

	subList, err := a.dynamicClient.Resource(subscriptionGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		// OLM not installed or not available — not an error
		logrus.WithError(err).Debug("Subscriptions not available, skipping operator collection")
		return nil
	}

	var operators []*pb.OperatorInfo
	for i := range subList.Items {
		sub := &subList.Items[i]
		namespace := sub.GetNamespace()

		installedCSV, found, _ := unstructured.NestedString(sub.Object, "status", "installedCSV")
		if !found || installedCSV == "" {
			continue
		}

		csv, err := a.dynamicClient.Resource(csvGVR).Namespace(namespace).Get(ctx, installedCSV, metav1.GetOptions{})
		if err != nil {
			continue
		}

		op := a.extractOperatorProto(csv, sub)
		if op != nil {
			operators = append(operators, op)
		}
	}

	if len(operators) > 0 {
		logrus.Debugf("Collected %d operators", len(operators))
	}
	return operators
}

// extractOperatorProto extracts operator info from CSV and subscription into proto format.
func (a *Agent) extractOperatorProto(csv, sub *unstructured.Unstructured) *pb.OperatorInfo {
	spec, found, _ := unstructured.NestedMap(csv.Object, "spec")
	if !found {
		return nil
	}

	op := &pb.OperatorInfo{
		Name:               csv.GetName(),
		InstalledNamespace: csv.GetNamespace(),
	}

	if v, ok := spec["displayName"].(string); ok {
		op.DisplayName = v
	} else {
		op.DisplayName = csv.GetName()
	}
	if v, ok := spec["version"].(string); ok {
		op.Version = v
	}
	if v, _, _ := unstructured.NestedString(spec, "provider", "name"); v != "" {
		op.Provider = v
	}

	// Install modes
	if modes, found, _ := unstructured.NestedSlice(spec, "installModes"); found {
		for _, mode := range modes {
			if m, ok := mode.(map[string]any); ok {
				if name, _ := m["type"].(string); name != "" {
					if supported, _ := m["supported"].(bool); supported {
						op.InstallModes = append(op.InstallModes, name)
						if name == "AllNamespaces" {
							op.IsClusterWide = true
							op.InstallMode = "AllNamespaces"
						}
					}
				}
			}
		}
		if op.InstallMode == "" {
			op.InstallMode = "SingleNamespace"
		}
	}

	// Subscription info
	if subSpec, found, _ := unstructured.NestedMap(sub.Object, "spec"); found {
		if v, ok := subSpec["installPlanApproval"].(string); ok {
			op.Subscription = map[string]string{"installPlanApproval": v}
		}
		// Check WATCH_NAMESPACE env for available namespaces
		if config, found, _ := unstructured.NestedMap(subSpec, "config"); found {
			if envList, found, _ := unstructured.NestedSlice(config, "env"); found {
				for _, e := range envList {
					if em, ok := e.(map[string]any); ok {
						if name, _ := em["name"].(string); name == "WATCH_NAMESPACE" {
							if value, _ := em["value"].(string); value != "" {
								op.AvailableInNamespaces = strings.Split(value, ",")
							}
						}
					}
				}
			}
		}
	}

	// Determine availability
	if op.IsClusterWide {
		op.AvailableInNamespaces = []string{"*"}
	} else if len(op.AvailableInNamespaces) == 0 {
		annotations := csv.GetAnnotations()
		if targetNs, ok := annotations["olm.targetNamespaces"]; ok && targetNs != "" {
			targetNs = strings.Trim(targetNs, `"'`)
			if targetNs != "" {
				op.AvailableInNamespaces = strings.Split(targetNs, ",")
			}
		} else {
			op.AvailableInNamespaces = []string{op.InstalledNamespace}
		}
	}
	op.AvailableCount = int32(len(op.AvailableInNamespaces))

	// Status from CSV
	if phase, _, _ := unstructured.NestedString(csv.Object, "status", "phase"); phase != "" {
		op.Status = phase
	} else {
		op.Status = "Unknown"
	}

	return op
}

// collectClusterOperators queries OpenShift ClusterOperators.
func (a *Agent) collectClusterOperators(ctx context.Context) []*pb.ClusterOperatorInfo {
	gvr := schema.GroupVersionResource{
		Group: "config.openshift.io", Version: "v1", Resource: "clusteroperators",
	}

	coList, err := a.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.WithError(err).Debug("ClusterOperators not available, skipping")
		return nil
	}

	var result []*pb.ClusterOperatorInfo
	for i := range coList.Items {
		co := a.extractClusterOperatorProto(&coList.Items[i])
		if co != nil {
			result = append(result, co)
		}
	}

	if len(result) > 0 {
		logrus.Debugf("Collected %d cluster operators", len(result))
	}
	return result
}

func (a *Agent) extractClusterOperatorProto(co *unstructured.Unstructured) *pb.ClusterOperatorInfo {
	info := &pb.ClusterOperatorInfo{Name: co.GetName()}

	status, found, _ := unstructured.NestedMap(co.Object, "status")
	if !found {
		return info
	}

	// Conditions
	if conditions, found, _ := unstructured.NestedSlice(status, "conditions"); found {
		for _, cond := range conditions {
			cm, ok := cond.(map[string]any)
			if !ok {
				continue
			}
			pbCond := &pb.ClusterOperatorCondition{
				Type:    strVal(cm, "type"),
				Status:  strVal(cm, "status"),
				Reason:  strVal(cm, "reason"),
				Message: strVal(cm, "message"),
			}
			info.Conditions = append(info.Conditions, pbCond)

			switch pbCond.Type {
			case "Available":
				info.Available = pbCond.Status == "True"
				if pbCond.Status != "True" && pbCond.Message != "" {
					info.Message = pbCond.Message
					info.Reason = pbCond.Reason
				}
			case "Progressing":
				info.Progressing = pbCond.Status == "True"
				if pbCond.Status == "True" && pbCond.Message != "" && info.Message == "" {
					info.Message = pbCond.Message
				}
			case "Degraded":
				info.Degraded = pbCond.Status == "True"
				if pbCond.Status == "True" && pbCond.Message != "" {
					info.Message = pbCond.Message
					info.Reason = pbCond.Reason
				}
			case "Upgradeable":
				info.Upgradeable = pbCond.Status == "True"
			}
		}
	}

	// Versions
	if versions, found, _ := unstructured.NestedSlice(status, "versions"); found {
		for _, ver := range versions {
			if vm, ok := ver.(map[string]any); ok {
				v := &pb.ClusterOperatorVersion{
					Name:    strVal(vm, "name"),
					Version: strVal(vm, "version"),
				}
				info.Versions = append(info.Versions, v)
				if v.Name == "operator" || v.Name == info.Name {
					info.Version = v.Version
				}
			}
		}
	}
	if info.Version == "" && len(info.Versions) > 0 {
		info.Version = info.Versions[0].Version
	}

	// Related objects
	if relObjs, found, _ := unstructured.NestedSlice(status, "relatedObjects"); found {
		for _, obj := range relObjs {
			if om, ok := obj.(map[string]any); ok {
				info.RelatedObjects = append(info.RelatedObjects, &pb.RelatedObject{
					Group:     strVal(om, "group"),
					Resource:  strVal(om, "resource"),
					Namespace: strVal(om, "namespace"),
					Name:      strVal(om, "name"),
				})
			}
		}
	}

	return info
}

// collectClusterInfo gathers cluster version and identity information.
func (a *Agent) collectClusterInfo(ctx context.Context) *pb.ClusterInfo {
	info := &pb.ClusterInfo{}

	// Try OpenShift ClusterVersion first
	cvGVR := schema.GroupVersionResource{
		Group: "config.openshift.io", Version: "v1", Resource: "clusterversions",
	}
	cv, err := a.dynamicClient.Resource(cvGVR).Get(ctx, "version", metav1.GetOptions{})
	if err == nil {
		info.Platform = "OpenShift"
		if spec, found, _ := unstructured.NestedMap(cv.Object, "spec"); found {
			if v, ok := spec["channel"].(string); ok {
				info.Channel = v
			}
			if v, ok := spec["clusterID"].(string); ok {
				info.ClusterId = v
			}
		}
		if desired, found, _ := unstructured.NestedMap(cv.Object, "status", "desired"); found {
			if v, ok := desired["version"].(string); ok {
				info.Version = v
			}
		}
	} else {
		// Fallback to standard K8s version
		ver, err := a.clientset.Discovery().ServerVersion()
		if err == nil {
			info.Version = ver.GitVersion
			info.Platform = ver.Platform
		}
	}

	// Try to get console URL
	routeGVR := schema.GroupVersionResource{
		Group: "route.openshift.io", Version: "v1", Resource: "routes",
	}
	consoleRoute, err := a.dynamicClient.Resource(routeGVR).Namespace("openshift-console").Get(ctx, "console", metav1.GetOptions{})
	if err == nil {
		if host, found, _ := unstructured.NestedString(consoleRoute.Object, "spec", "host"); found && host != "" {
			_, hasTLS, _ := unstructured.NestedMap(consoleRoute.Object, "spec", "tls")
			if hasTLS {
				info.ConsoleUrl = "https://" + host
			} else {
				info.ConsoleUrl = "http://" + host
			}
		}
	}

	return info
}

// strVal safely extracts a string from a map.
func strVal(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func (a *Agent) flushBuffer(ctx context.Context, stream pb.CollectorService_ConnectClient) {
	for {
		batch := a.buffer.Pop()
		if batch == nil {
			return
		}
		if err := stream.Send(&pb.ConnectRequest{
			Payload: &pb.ConnectRequest_Metrics{Metrics: batch},
		}); err != nil {
			// Put it back
			a.buffer.Push(batch)
			return
		}
		logrus.Debug("Flushed buffered batch")
	}
}

func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case int32:
		return float64(val), true
	default:
		return 0, false
	}
}
