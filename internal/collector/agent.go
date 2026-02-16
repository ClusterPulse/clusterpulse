package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	mscollector "github.com/clusterpulse/cluster-controller/internal/metricsource/collector"
	"github.com/clusterpulse/cluster-controller/internal/version"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/clusterpulse/cluster-controller/pkg/utils"
	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	startTime time.Time
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

	// Connect to ingester
	conn, err := grpc.NewClient(
		a.config.IngesterAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()
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
	if err := stream.Send(&pb.CollectorMessage{
		Payload: &pb.CollectorMessage_Register{
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

			if err := stream.Send(&pb.CollectorMessage{
				Payload: &pb.CollectorMessage_Metrics{Metrics: batch},
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
			if err := stream.Send(&pb.CollectorMessage{
				Payload: &pb.CollectorMessage_Health{
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
		case *pb.IngesterMessage_Config:
			a.applyConfig(payload.Config)
			log.Infof("Received config update: %d metric sources", len(payload.Config.MetricSourcesJson))

		case *pb.IngesterMessage_Ack:
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
		} else {
			cm.NodesNotReady++
		}
		cm.CpuCapacity += nm.CpuCapacity
		cm.CpuAllocatable += nm.CpuAllocatable
		cm.CpuRequested += nm.CpuRequested
		cm.MemoryCapacity += nm.MemoryCapacity
		cm.MemoryAllocatable += nm.MemoryAllocatable
		cm.MemoryRequested += nm.MemoryRequested
		cm.StorageCapacity += nm.StorageCapacity
		cm.Pods += nm.PodsTotal
		cm.PodsRunning += nm.PodsRunning
		cm.PodsPending += nm.PodsPending
		cm.PodsFailed += nm.PodsFailed
	}

	cm.Nodes = int32(len(nodes.Items))
	if cm.CpuAllocatable > 0 {
		cm.CpuUsagePercent = (cm.CpuRequested / cm.CpuAllocatable) * 100
	}
	if cm.MemoryAllocatable > 0 {
		cm.MemoryUsagePercent = float64(cm.MemoryRequested) / float64(cm.MemoryAllocatable) * 100
	}

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
	if sts, err := a.clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{}); err == nil {
		cm.Statefulsets = int32(len(sts.Items))
	}
	if ds, err := a.clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{}); err == nil {
		cm.Daemonsets = int32(len(ds.Items))
	}
	if svcs, err := a.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{}); err == nil {
		cm.Services = int32(len(svcs.Items))
	}
	if pvcs, err := a.clientset.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{}); err == nil {
		cm.Pvcs = int32(len(pvcs.Items))
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
		if len(label) > 23 && label[:23] == "node-role.kubernetes.io/" {
			nm.Roles = append(nm.Roles, label[23:])
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

func (a *Agent) flushBuffer(ctx context.Context, stream pb.CollectorService_ConnectClient) {
	for {
		batch := a.buffer.Pop()
		if batch == nil {
			return
		}
		if err := stream.Send(&pb.CollectorMessage{
			Payload: &pb.CollectorMessage_Metrics{Metrics: batch},
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
