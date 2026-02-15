package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/rbac"
	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/sirupsen/logrus"
)

// Server wraps the HTTP server with graceful shutdown.
type Server struct {
	httpServer *http.Server
	router     *chi.Mux
}

// NewServer creates a configured API server.
func NewServer(cfg *APIConfig, s *store.Client, engine *rbac.Engine) *Server {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Forwarded-User", "X-Forwarded-Email"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
	r.Use(SecurityHeaders)

	// Health endpoints (no auth)
	r.Get("/healthz", HealthHandler)
	r.Get("/readyz", ReadyHandler(s))

	// Handlers
	clusterH := NewClusterHandler(s, engine)
	authH := NewAuthHandler(s, engine, cfg)
	regH := NewRegistryHandler(s)
	customH := NewCustomTypeHandler(s, engine)

	var historyH *HistoryHandler
	if cfg.VMEnabled {
		historyH = NewHistoryHandler(cfg.VMEndpoint, engine)
	}

	r.Route("/api/v1", func(r chi.Router) {
		// Auth routes (mixed auth requirements)
		r.Route("/auth", func(r chi.Router) {
			r.With(OptionalAuthMiddleware(cfg)).Get("/status", authH.AuthStatus)
			r.Group(func(r chi.Router) {
				r.Use(AuthMiddleware(cfg))
				r.Get("/me", authH.GetMe)
				r.Get("/permissions", authH.GetPermissions)
				r.Get("/policies", authH.GetPolicies)
				r.Post("/logout", authH.Logout)
				r.Post("/cache/clear", authH.ClearCache)
			})
		})

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(AuthMiddleware(cfg))

			r.Get("/registries/status", regH.ListRegistriesStatus)

			r.Route("/clusters", func(r chi.Router) {
				r.Get("/", clusterH.ListClusters)

				r.Route("/{name}", func(r chi.Router) {
					r.Get("/", clusterH.GetCluster)
					r.Get("/nodes", clusterH.GetClusterNodes)
					r.Get("/nodes/{node}", clusterH.GetClusterNode)
					r.Get("/operators", clusterH.GetClusterOperators)
					r.Get("/namespaces", clusterH.GetClusterNamespaces)
					r.Get("/alerts", clusterH.GetClusterAlerts)
					r.Get("/events", clusterH.GetClusterEvents)
					r.Get("/custom/{type}", clusterH.GetCustomResources)

					// History endpoints (require VictoriaMetrics)
					if historyH != nil {
						r.Get("/metrics/history", historyH.GetClusterMetricsHistory)
						r.Get("/nodes/{node}/metrics/history", historyH.GetNodeMetricsHistory)
					}
				})
			})

			r.Route("/custom-types", func(r chi.Router) {
				r.Get("/", customH.ListCustomTypes)
				r.Get("/clusters", customH.GetCustomResourceCounts)
			})
		})
	})

	return &Server{
		httpServer: &http.Server{
			Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Handler:      r,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		router: r,
	}
}

// Start runs the HTTP server and blocks until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		logrus.Infof("API server listening on %s", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		logrus.Info("Shutting down API server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
