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
	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/client-go/dynamic"
)

// Agent is the collector agent that runs on managed clusters.
// It collects metrics locally and pushes them to the hub ingester via gRPC.
type Agent struct {
	config  *Config
	collect *mscollector.Collector

	// K8s dynamic client for in-cluster collection
	dynamicClient dynamic.Interface

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
func NewAgent(cfg *Config, dynamicClient dynamic.Interface) *Agent {
	return &Agent{
		config:        cfg,
		collect:       mscollector.NewCollector(),
		dynamicClient: dynamicClient,
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
