package ingester

import (
	"fmt"
	"net"
	"sync"

	"github.com/clusterpulse/cluster-controller/internal/config"
	redis "github.com/clusterpulse/cluster-controller/internal/store"
	pb "github.com/clusterpulse/cluster-controller/proto/collectorpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"time"
)

// Server is the gRPC ingester that accepts metrics from collector agents.
type Server struct {
	pb.UnimplementedCollectorServiceServer

	config      *config.Config
	redisClient *redis.Client
	vmWriter    *VMWriter
	grpcServer  *grpc.Server
	handler     *Handler

	// Track connected collectors
	mu          sync.RWMutex
	connections map[string]*collectorConn // cluster name -> connection info
}

type collectorConn struct {
	clusterName   string
	version       string
	connectedAt   time.Time
	lastHeartbeat time.Time
}

// NewServer creates a new ingester gRPC server.
func NewServer(cfg *config.Config, redisClient *redis.Client) *Server {
	var vmw *VMWriter
	if cfg.VMEnabled {
		vmw = NewVMWriter(cfg.VMEndpoint)
		logrus.WithField("endpoint", cfg.VMEndpoint).Info("VictoriaMetrics writer enabled")
	} else {
		logrus.Info("VictoriaMetrics writer disabled (VM_ENABLED not set)")
	}

	s := &Server{
		config:      cfg,
		redisClient: redisClient,
		vmWriter:    vmw,
		connections: make(map[string]*collectorConn),
	}

	s.handler = NewHandler(redisClient, vmw)

	s.grpcServer = grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)

	pb.RegisterCollectorServiceServer(s.grpcServer, s)
	return s
}

// Start begins listening for collector connections.
func (s *Server) Start(port int) error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	logrus.WithField("port", port).Info("Ingester gRPC server starting")

	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			logrus.WithError(err).Error("Ingester gRPC server failed")
		}
	}()

	return nil
}

// Stop gracefully shuts down the gRPC server.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
	logrus.Info("Ingester gRPC server stopped")
}

// Connect implements the bidirectional streaming RPC.
func (s *Server) Connect(stream pb.CollectorService_ConnectServer) error {
	log := logrus.WithField("component", "ingester")

	var clusterName string

	for {
		msg, err := stream.Recv()
		if err != nil {
			if clusterName != "" {
				s.removeConnection(clusterName)
				log.WithField("cluster", clusterName).Info("Collector disconnected")
			}
			return err
		}

		switch payload := msg.Payload.(type) {
		case *pb.CollectorMessage_Register:
			clusterName = payload.Register.ClusterName
			if clusterName == "" {
				return fmt.Errorf("register: cluster_name is required")
			}
			// TODO: validate token against ClusterConnection credentials
			s.addConnection(clusterName, payload.Register.Version)
			log.WithFields(logrus.Fields{
				"cluster": clusterName,
				"version": payload.Register.Version,
			}).Info("Collector registered")

			// Send initial config
			configMsg, err := s.handler.BuildConfigUpdate(stream.Context(), clusterName)
			if err != nil {
				log.WithError(err).Warn("Failed to build initial config")
			} else if configMsg != nil {
				if err := stream.Send(&pb.IngesterMessage{
					Payload: &pb.IngesterMessage_Config{Config: configMsg},
				}); err != nil {
					return fmt.Errorf("failed to send config: %w", err)
				}
			}

		case *pb.CollectorMessage_Metrics:
			if clusterName == "" {
				return fmt.Errorf("metrics received before registration")
			}

			batch := payload.Metrics
			ackErr := s.handler.ProcessBatch(stream.Context(), batch)

			ack := &pb.Ack{
				BatchId: batch.BatchId,
				Success: ackErr == nil,
			}
			if ackErr != nil {
				ack.Error = ackErr.Error()
				log.WithError(ackErr).Warn("Failed to process metrics batch")
			} else {
				log.WithFields(logrus.Fields{
					"cluster":          clusterName,
					"batch_id":         batch.BatchId,
					"nodes":            len(batch.NodeMetrics),
					"custom_resources": len(batch.CustomResources),
				}).Debug("Processed metrics batch")
			}

			if err := stream.Send(&pb.IngesterMessage{
				Payload: &pb.IngesterMessage_Ack{Ack: ack},
			}); err != nil {
				return fmt.Errorf("failed to send ack: %w", err)
			}

		case *pb.CollectorMessage_Health:
			if clusterName == "" {
				return fmt.Errorf("health received before registration")
			}
			s.updateHeartbeat(clusterName)
			log.WithField("cluster", clusterName).Debug("Heartbeat received")
		}
	}
}

// IsConnected returns whether a collector is connected for the given cluster.
func (s *Server) IsConnected(clusterName string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.connections[clusterName]
	return ok
}

// GetConnectionInfo returns connection details for a cluster, or nil if not connected.
func (s *Server) GetConnectionInfo(clusterName string) (connected bool, lastHeartbeat time.Time, version string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	conn, ok := s.connections[clusterName]
	if !ok {
		return false, time.Time{}, ""
	}
	return true, conn.lastHeartbeat, conn.version
}

func (s *Server) addConnection(clusterName, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections[clusterName] = &collectorConn{
		clusterName:   clusterName,
		version:       version,
		connectedAt:   time.Now(),
		lastHeartbeat: time.Now(),
	}
}

func (s *Server) removeConnection(clusterName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.connections, clusterName)
}

func (s *Server) updateHeartbeat(clusterName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if conn, ok := s.connections[clusterName]; ok {
		conn.lastHeartbeat = time.Now()
	}
}
