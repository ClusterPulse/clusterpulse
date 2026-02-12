package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/clusterpulse/cluster-controller/internal/rbac"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type contextKey string

const principalKey contextKey = "principal"

// GetPrincipal extracts the Principal from request context.
func GetPrincipal(r *http.Request) *rbac.Principal {
	if p, ok := r.Context().Value(principalKey).(*rbac.Principal); ok {
		return p
	}
	return nil
}

// AuthMiddleware creates an authentication middleware using OAuth proxy headers.
func AuthMiddleware(cfg *APIConfig) func(http.Handler) http.Handler {
	dynClient := initDynamicClient()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health endpoints
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}

			username := r.Header.Get(cfg.OAuthHeaderUser)
			email := r.Header.Get(cfg.OAuthHeaderEmail)

			// Dev mode fallback
			if username == "" && cfg.IsDevelopment() && !cfg.OAuthProxyEnabled {
				principal := &rbac.Principal{
					Username: "dev-user",
					Email:    "dev@clusterpulse.local",
					Groups:   []string{"developers", "cluster-viewers"},
				}
				ctx := context.WithValue(r.Context(), principalKey, principal)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if username == "" {
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}

			groups := resolveGroups(r.Context(), dynClient, username, cfg.IsDevelopment())

			principal := &rbac.Principal{
				Username:         username,
				Email:            email,
				Groups:           groups,
				IsServiceAccount: strings.HasPrefix(username, "system:serviceaccount:"),
			}

			ctx := context.WithValue(r.Context(), principalKey, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuthMiddleware works like AuthMiddleware but sets principal to nil
// instead of returning 401 when no user header is present.
func OptionalAuthMiddleware(cfg *APIConfig) func(http.Handler) http.Handler {
	dynClient := initDynamicClient()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username := r.Header.Get(cfg.OAuthHeaderUser)
			email := r.Header.Get(cfg.OAuthHeaderEmail)

			if username == "" && cfg.IsDevelopment() && !cfg.OAuthProxyEnabled {
				// Dev mode: still set nil principal (caller checks)
				next.ServeHTTP(w, r)
				return
			}

			if username == "" {
				// No auth — proceed with nil principal
				next.ServeHTTP(w, r)
				return
			}

			groups := resolveGroups(r.Context(), dynClient, username, cfg.IsDevelopment())
			principal := &rbac.Principal{
				Username:         username,
				Email:            email,
				Groups:           groups,
				IsServiceAccount: strings.HasPrefix(username, "system:serviceaccount:"),
			}
			ctx := context.WithValue(r.Context(), principalKey, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SecurityHeaders adds standard security headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// resolveGroups resolves user groups from OpenShift User/Group resources.
func resolveGroups(ctx context.Context, dynClient dynamic.Interface, username string, isDev bool) []string {
	if dynClient == nil {
		if isDev {
			return []string{"developers", "cluster-viewers"}
		}
		return nil
	}

	userGVR := schema.GroupVersionResource{
		Group:    "user.openshift.io",
		Version:  "v1",
		Resource: "users",
	}

	// Try to get groups from User resource
	user, err := dynClient.Resource(userGVR).Get(ctx, username, metav1.GetOptions{})
	if err == nil {
		if groups, ok := user.Object["groups"].([]any); ok {
			result := make([]string, 0, len(groups))
			for _, g := range groups {
				if s, ok := g.(string); ok {
					result = append(result, s)
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}

	// Fallback: iterate Group resources
	groupGVR := schema.GroupVersionResource{
		Group:    "user.openshift.io",
		Version:  "v1",
		Resource: "groups",
	}

	groupList, err := dynClient.Resource(groupGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.WithError(err).Debug("Failed to list OpenShift groups")
		if isDev {
			return []string{"developers", "cluster-viewers"}
		}
		return nil
	}

	var groups []string
	for _, g := range groupList.Items {
		users, ok := g.Object["users"].([]any)
		if !ok {
			continue
		}
		for _, u := range users {
			if s, ok := u.(string); ok && s == username {
				groups = append(groups, g.GetName())
				break
			}
		}
	}

	return groups
}

func initDynamicClient() dynamic.Interface {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil).ClientConfig()
		if err != nil {
			logrus.WithError(err).Debug("No kubernetes config available, group resolution disabled")
			return nil
		}
	}

	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		logrus.WithError(err).Warn("Failed to create dynamic client")
		return nil
	}

	return client
}
