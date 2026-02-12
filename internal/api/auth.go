package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/rbac"
	store "github.com/clusterpulse/cluster-controller/internal/store"
	"github.com/sirupsen/logrus"
)

// AuthHandler handles authentication-related API routes.
type AuthHandler struct {
	store  *store.Client
	engine *rbac.Engine
	cfg    *APIConfig
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(s *store.Client, engine *rbac.Engine, cfg *APIConfig) *AuthHandler {
	return &AuthHandler{store: s, engine: engine, cfg: cfg}
}

// AuthStatus returns the current authentication status (works with optional auth).
func (h *AuthHandler) AuthStatus(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"message":       "User is authenticated",
			"user": map[string]any{
				"username": principal.Username,
				"email":    principal.Email,
				"groups":   principal.Groups,
			},
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": false,
		"message":       "User is not authenticated",
	})
}

// GetMe returns the current authenticated user information.
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	logrus.Infof("User information requested for %s", principal.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"username": principal.Username,
		"email":    principal.Email,
		"groups":   principal.Groups,
	})
}

// GetPermissions returns per-cluster permission summary for the current user.
func (h *AuthHandler) GetPermissions(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	ctx := r.Context()
	accessible := h.engine.GetAccessibleClusters(ctx, principal)

	clusterPerms := make(map[string]any, len(accessible))
	for _, name := range accessible {
		resource := &rbac.Resource{Type: rbac.ResourceCluster, Name: name, Cluster: name}
		perms := h.engine.GetPermissions(ctx, principal, resource)

		permList := make([]string, 0, len(perms))
		for action := range perms {
			permList = append(permList, string(action))
		}
		sort.Strings(permList)

		level := "limited"
		if len(perms) > 5 {
			level = "full"
		}

		clusterPerms[name] = map[string]any{
			"permissions":  permList,
			"access_level": level,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"username": principal.Username,
			"email":    principal.Email,
			"groups":   principal.Groups,
		},
		"summary": map[string]any{
			"total_clusters":      len(accessible),
			"accessible_clusters": len(accessible),
		},
		"clusters":                 clusterPerms,
		"accessible_cluster_names": accessible,
		"evaluated_at":             time.Now().UTC().Format(time.RFC3339),
	})

	logrus.Infof("User %s permissions retrieved (%d clusters)", principal.Username, len(accessible))
}

// GetPolicies returns all policies that apply to the current user.
func (h *AuthHandler) GetPolicies(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	ctx := r.Context()
	rdb := h.store.RedisClient()

	type policyEntry struct {
		Source   string         `json:"source"`
		Policy   map[string]any `json:"policy"`
		Priority int            `json:"priority"`
	}

	seen := make(map[string]struct{})
	var policies []policyEntry

	// User policies
	userKey := fmt.Sprintf("policy:user:%s:sorted", principal.Username)
	userResults, err := rdb.ZRevRangeWithScores(ctx, userKey, 0, -1).Result()
	if err == nil {
		for _, z := range userResults {
			policyKey := z.Member.(string)
			if _, ok := seen[policyKey]; ok {
				continue
			}
			seen[policyKey] = struct{}{}

			data, err := rdb.HGet(ctx, policyKey, "data").Result()
			if err != nil {
				continue
			}
			var policy map[string]any
			if err := json.Unmarshal([]byte(data), &policy); err != nil {
				continue
			}
			policies = append(policies, policyEntry{
				Source:   "user",
				Policy:   policy,
				Priority: int(z.Score),
			})
		}
	}

	// Group policies
	for _, group := range principal.Groups {
		groupKey := fmt.Sprintf("policy:group:%s:sorted", group)
		groupResults, err := rdb.ZRevRangeWithScores(ctx, groupKey, 0, -1).Result()
		if err != nil {
			continue
		}
		for _, z := range groupResults {
			policyKey := z.Member.(string)
			if _, ok := seen[policyKey]; ok {
				continue
			}
			seen[policyKey] = struct{}{}

			data, err := rdb.HGet(ctx, policyKey, "data").Result()
			if err != nil {
				continue
			}
			var policy map[string]any
			if err := json.Unmarshal([]byte(data), &policy); err != nil {
				continue
			}
			policies = append(policies, policyEntry{
				Source:   fmt.Sprintf("group:%s", group),
				Policy:   policy,
				Priority: int(z.Score),
			})
		}
	}

	// Sort by priority descending
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Priority > policies[j].Priority
	})

	evalOrder := make([]string, len(policies))
	for i, p := range policies {
		name, _ := p.Policy["policy_name"].(string)
		evalOrder[i] = name
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"username": principal.Username,
			"groups":   principal.Groups,
		},
		"total_policies":   len(policies),
		"policies":         policies,
		"evaluation_order": evalOrder,
		"retrieved_at":     time.Now().UTC().Format(time.RFC3339),
	})
}

// Logout clears RBAC and group caches for the current user.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	ctx := r.Context()
	h.engine.ClearCache(ctx, principal)

	rdb := h.store.RedisClient()
	rdb.Del(ctx, fmt.Sprintf("user:groups:%s", principal.Username))
	rdb.Del(ctx, fmt.Sprintf("user:permissions:%s", principal.Username))

	logrus.Infof("User %s logged out", principal.Username)

	resp := map[string]any{"message": "Logout successful"}
	if h.cfg.OAuthProxyEnabled && !h.cfg.IsDevelopment() {
		resp["redirect"] = "/oauth2/sign_out"
	}

	writeJSON(w, http.StatusOK, resp)
}

// ClearCache clears RBAC cache for the current user.
func (h *AuthHandler) ClearCache(w http.ResponseWriter, r *http.Request) {
	principal := GetPrincipal(r)
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	ctx := r.Context()
	count := h.engine.ClearCache(ctx, principal)

	rdb := h.store.RedisClient()
	rdb.Del(ctx, fmt.Sprintf("user:groups:%s", principal.Username))
	rdb.Del(ctx, fmt.Sprintf("user:permissions:%s", principal.Username))

	logrus.Infof("Cleared cache for user %s", principal.Username)

	writeJSON(w, http.StatusOK, map[string]any{
		"message":              "Cache cleared successfully",
		"rbac_entries_cleared": count,
		"user":                 principal.Username,
	})
}
