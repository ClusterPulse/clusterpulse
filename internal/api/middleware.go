package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/rbac"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
	cache := newGroupCache(time.Duration(cfg.GroupCacheTTL) * time.Second)

	// Log a prominent warning if running in dev mode.
	if cfg.IsDevelopment() && !cfg.OAuthProxyEnabled {
		logrus.Warn("SECURITY: Running in development mode with OAuth proxy disabled — dev-user auth fallback is active")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health endpoints
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}

			username := r.Header.Get(cfg.OAuthHeaderUser)
			email := r.Header.Get(cfg.OAuthHeaderEmail)

			// Dev mode fallback only when explicitly enabled.
			if username == "" && cfg.IsDevelopment() && !cfg.OAuthProxyEnabled && cfg.EnableDevAuth {
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

			canonical, groups := resolveGroupsCached(r.Context(), cache, dynClient, username, email, cfg.IsDevelopment())

			principal := &rbac.Principal{
				Username:         canonical,
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
	cache := newGroupCache(time.Duration(cfg.GroupCacheTTL) * time.Second)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username := r.Header.Get(cfg.OAuthHeaderUser)
			email := r.Header.Get(cfg.OAuthHeaderEmail)

			// Apply same dev-user fallback as AuthMiddleware for consistency.
			if username == "" && cfg.IsDevelopment() && !cfg.OAuthProxyEnabled && cfg.EnableDevAuth {
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
				// No auth — proceed with nil principal
				next.ServeHTTP(w, r)
				return
			}

			canonical, groups := resolveGroupsCached(r.Context(), cache, dynClient, username, email, cfg.IsDevelopment())
			principal := &rbac.Principal{
				Username:         canonical,
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

// resolveGroups resolves the canonical OpenShift principal identity and its
// group memberships. It returns (canonicalUsername, groups).
//
// Background: openshift/oauth-proxy serializes its session cookie with the
// user's email as the first field, then decodes it by splitting on "@" and
// keeping only the local part as session.User. The result is that
// X-Forwarded-User is the local-part of the email, while X-Forwarded-Email
// is the full email — and the OpenShift User CR's metadata.name is the full
// email. Looking up User by X-Forwarded-User therefore 404s. We retry the
// lookup with the email, and if that resolves a real User CR we canonicalize
// the principal username to that name so the rest of the API (policies,
// cache keys, Group.users[] matching) consistently uses the OpenShift
// identity.
//
// Service accounts (`system:serviceaccount:...`) are never canonicalized.
//
// Emits a per-request INFO log of the resolved groups so misconfigured
// group resolution (missing User CR, missing RBAC on user.openshift.io
// resources, broken group sync) is visible in logs.
func resolveGroups(ctx context.Context, dynClient dynamic.Interface, username, email string, isDev bool) (string, []string) {
	if dynClient == nil {
		if isDev {
			groups := []string{"developers", "cluster-viewers"}
			logResolvedGroups(username, groups, "dev-fallback (no dynamic client)")
			return username, groups
		}
		logResolvedGroups(username, nil, "no dynamic client")
		return username, nil
	}

	// Build the list of identifiers to try, in order. Username first (matches
	// session.User). Email second when it differs (matches the canonical
	// OpenShift User.metadata.name when the OAuth IDP mappingMethod is email).
	// Service accounts always carry a "system:serviceaccount:..." username and
	// are never canonicalized, so don't fall back to email for them.
	candidates := []string{username}
	if email != "" && email != username && !strings.HasPrefix(username, "system:serviceaccount:") {
		candidates = append(candidates, email)
	}

	userGVR := schema.GroupVersionResource{
		Group:    "user.openshift.io",
		Version:  "v1",
		Resource: "users",
	}
	groupGVR := schema.GroupVersionResource{
		Group:    "user.openshift.io",
		Version:  "v1",
		Resource: "groups",
	}

	// Step 1: try each candidate against the User CR until one resolves.
	// If the User exists with non-empty groups, return immediately with that
	// identity as canonical.
	var canonical string
	var userLookupErr error
	for _, ident := range candidates {
		user, err := dynClient.Resource(userGVR).Get(ctx, ident, metav1.GetOptions{})
		if err != nil {
			userLookupErr = err
			continue
		}
		canonical = ident
		groups := extractUserGroups(user)
		if len(groups) > 0 {
			logResolvedGroups(canonical, groups, "user.openshift.io User.groups (canonicalized to "+canonical+")")
			return canonical, groups
		}
		// User CR exists but its .groups is empty/null. Fall through to the
		// Group list scan — but remember we have a canonical identity now.
		break
	}
	if canonical == "" && userLookupErr != nil {
		logrus.WithError(userLookupErr).Warnf("resolveGroups: no user.openshift.io User CR found for any of %v; falling back to Group list", candidates)
	}

	// Step 2: scan Groups for membership. Try the canonical identifier first
	// if we found a User CR, otherwise try each candidate.
	groupList, err := dynClient.Resource(groupGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.WithError(err).Warnf("resolveGroups: failed to list OpenShift Groups for user %q", username)
		if isDev {
			groups := []string{"developers", "cluster-viewers"}
			logResolvedGroups(username, groups, "dev-fallback (Group list failed)")
			return username, groups
		}
		logResolvedGroups(username, nil, "Group list failed")
		return username, nil
	}

	scanOrder := candidates
	if canonical != "" {
		// Prefer the canonical identity first; keep the others as backup so
		// admins who listed the short username in Group.users[] still match.
		scanOrder = append([]string{canonical}, diffWithout(candidates, canonical)...)
	}
	for _, ident := range scanOrder {
		if groups := findGroupsContainingUser(groupList.Items, ident); len(groups) > 0 {
			logResolvedGroups(ident, groups, "Group list scan (canonicalized to "+ident+")")
			return ident, groups
		}
	}

	// No groups found anywhere. Return the canonical identity if we have one
	// (so policies that name the OpenShift identity still match), else fall
	// back to the original username.
	identity := username
	if canonical != "" {
		identity = canonical
	}
	logResolvedGroups(identity, nil, "no Group membership found")
	return identity, nil
}

// extractUserGroups pulls the .groups []string field from an OpenShift User CR.
func extractUserGroups(user *unstructured.Unstructured) []string {
	groups, ok := user.Object["groups"].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(groups))
	for _, g := range groups {
		if s, ok := g.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// findGroupsContainingUser returns the names of Groups whose users[] array
// contains exactly `ident`.
func findGroupsContainingUser(items []unstructured.Unstructured, ident string) []string {
	var groups []string
	for _, g := range items {
		users, ok := g.Object["users"].([]any)
		if !ok {
			continue
		}
		for _, u := range users {
			if s, ok := u.(string); ok && s == ident {
				groups = append(groups, g.GetName())
				break
			}
		}
	}
	return groups
}

// diffWithout returns a copy of `xs` with `drop` removed (first occurrence).
func diffWithout(xs []string, drop string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}

// logResolvedGroups emits a structured INFO log of the groups attached to
// a Principal at request time. Crucial signal when diagnosing RBAC outages.
func logResolvedGroups(username string, groups []string, source string) {
	logrus.WithFields(logrus.Fields{
		"user":   username,
		"groups": groups,
		"source": source,
	}).Info("resolved principal groups")
}

// groupCacheEntry holds a single cached resolveGroups result.
type groupCacheEntry struct {
	canonical string
	groups    []string
	expiresAt time.Time
}

// groupCache is a small in-memory TTL cache that coalesces duplicate
// resolveGroups calls during a single page load. Per-pod, mutex-protected.
// Caches both positive and "no groups" results so absent users don't keep
// hitting the OpenShift API every request. TTL <= 0 disables caching.
type groupCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]groupCacheEntry
}

func newGroupCache(ttl time.Duration) *groupCache {
	if ttl <= 0 {
		return nil
	}
	return &groupCache{
		ttl:     ttl,
		entries: make(map[string]groupCacheEntry),
	}
}

// groupCacheKey returns the cache key for a (username, email) pair. We embed
// a NUL separator so usernames containing the email value can't collide with
// neighbouring keys.
func groupCacheKey(username, email string) string {
	return username + "\x00" + email
}

func (c *groupCache) get(username, email string) (string, []string, bool) {
	if c == nil {
		return "", nil, false
	}
	key := groupCacheKey(username, email)
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.entries[key]
	if !ok {
		return "", nil, false
	}
	if time.Now().After(v.expiresAt) {
		delete(c.entries, key)
		return "", nil, false
	}
	return v.canonical, v.groups, true
}

func (c *groupCache) put(username, email, canonical string, groups []string) {
	if c == nil {
		return
	}
	key := groupCacheKey(username, email)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = groupCacheEntry{
		canonical: canonical,
		groups:    groups,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// resolveGroupsCached wraps resolveGroups with a short-TTL cache. The cache
// is keyed by the raw (username, email) headers — not by the canonicalized
// identity — so a single page load of N parallel requests with the same
// auth headers hits OpenShift at most once.
func resolveGroupsCached(ctx context.Context, cache *groupCache, dynClient dynamic.Interface, username, email string, isDev bool) (string, []string) {
	if canonical, groups, ok := cache.get(username, email); ok {
		return canonical, groups
	}
	canonical, groups := resolveGroups(ctx, dynClient, username, email, isDev)
	cache.put(username, email, canonical, groups)
	return canonical, groups
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
