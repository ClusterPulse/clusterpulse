package api

import (
	"slices"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// makeUser constructs a fake user.openshift.io/v1 User CR with the given name
// and groups list. A nil groups slice produces a User CR with `groups: null`
// (which is what oauth-server-managed Users typically look like before group sync).
func makeUser(name string, groups []string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("user.openshift.io/v1")
	u.SetKind("User")
	u.SetName(name)
	if groups != nil {
		raw := make([]any, len(groups))
		for i, g := range groups {
			raw[i] = g
		}
		u.Object["groups"] = raw
	} else {
		u.Object["groups"] = nil
	}
	return u
}

// makeGroup constructs a fake user.openshift.io/v1 Group with the given name
// and users list.
func makeGroup(name string, users []string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("user.openshift.io/v1")
	u.SetKind("Group")
	u.SetName(name)
	raw := make([]any, len(users))
	for i, x := range users {
		raw[i] = x
	}
	u.Object["users"] = raw
	return u
}

// newFakeDynClient returns a fake dynamic client preloaded with the supplied
// User and Group CRs. The List kinds for both resources are registered so
// resolveGroups' Group list-scan path works.
func newFakeDynClient(objs ...*unstructured.Unstructured) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	userGVR := schema.GroupVersionResource{Group: "user.openshift.io", Version: "v1", Resource: "users"}
	groupGVR := schema.GroupVersionResource{Group: "user.openshift.io", Version: "v1", Resource: "groups"}
	gvrToListKind := map[schema.GroupVersionResource]string{
		userGVR:  "UserList",
		groupGVR: "GroupList",
	}
	runtimeObjs := make([]runtime.Object, 0, len(objs))
	for _, o := range objs {
		runtimeObjs = append(runtimeObjs, o)
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrToListKind, runtimeObjs...)
}

func TestResolveGroups_UsernameHitsUserCR(t *testing.T) {
	dyn := newFakeDynClient(
		makeUser("alice", []string{"team-a", "team-b"}),
	)

	canonical, groups := resolveGroups(t.Context(), dyn, "alice", "alice@example.com", false)

	if canonical != "alice" {
		t.Errorf("canonical = %q, want %q", canonical, "alice")
	}
	if !slices.Equal(groups, []string{"team-a", "team-b"}) {
		t.Errorf("groups = %v, want [team-a team-b]", groups)
	}
}

func TestResolveGroups_EmailFallbackHitsUserCR(t *testing.T) {
	// Simulates the openshift/oauth-proxy session cookie bug: X-Forwarded-User
	// is the local-part of the email; the User CR's metadata.name is the full email.
	dyn := newFakeDynClient(
		makeUser("user1@gmail.com", []string{"engineering"}),
	)

	canonical, groups := resolveGroups(t.Context(), dyn, "user1", "user1@gmail.com", false)

	if canonical != "user1@gmail.com" {
		t.Errorf("canonical = %q, want %q (should canonicalize to the User CR's name)", canonical, "user1@gmail.com")
	}
	if !slices.Equal(groups, []string{"engineering"}) {
		t.Errorf("groups = %v, want [engineering]", groups)
	}
}

func TestResolveGroups_UserCRGroupsNullFallsBackToGroupListByCanonical(t *testing.T) {
	// Matches the bug report: User CR exists (named with the email) but its
	// groups field is null. The Group resource lists the canonical email
	// as a member. resolveGroups must canonicalize AND find the group via
	// the Group list scan.
	dyn := newFakeDynClient(
		makeUser("user1@gmail.com", nil),
		makeGroup("engineering", []string{"user1@gmail.com"}),
	)

	canonical, groups := resolveGroups(t.Context(), dyn, "user1", "user1@gmail.com", false)

	if canonical != "user1@gmail.com" {
		t.Errorf("canonical = %q, want %q", canonical, "user1@gmail.com")
	}
	if !slices.Equal(groups, []string{"engineering"}) {
		t.Errorf("groups = %v, want [engineering]", groups)
	}
}

func TestResolveGroups_GroupListContainsShortUsername(t *testing.T) {
	// No User CRs exist for either identifier. An admin added the short
	// username (the only thing they saw before this fix) to a Group.users[].
	// resolveGroups should still find it via the scan, preserving back-compat.
	dyn := newFakeDynClient(
		makeGroup("legacy", []string{"user1"}),
	)

	canonical, groups := resolveGroups(t.Context(), dyn, "user1", "user1@gmail.com", false)

	if canonical != "user1" {
		t.Errorf("canonical = %q, want %q (should fall back to original when no User CR exists)", canonical, "user1")
	}
	if !slices.Equal(groups, []string{"legacy"}) {
		t.Errorf("groups = %v, want [legacy]", groups)
	}
}

func TestResolveGroups_GroupListContainsEmailIdentity(t *testing.T) {
	// No User CR for either form, but Group.users[] contains the email.
	dyn := newFakeDynClient(
		makeGroup("engineering", []string{"user1@gmail.com"}),
	)

	canonical, groups := resolveGroups(t.Context(), dyn, "user1", "user1@gmail.com", false)

	if canonical != "user1@gmail.com" {
		t.Errorf("canonical = %q, want %q", canonical, "user1@gmail.com")
	}
	if !slices.Equal(groups, []string{"engineering"}) {
		t.Errorf("groups = %v, want [engineering]", groups)
	}
}

func TestResolveGroups_ServiceAccountNotCanonicalized(t *testing.T) {
	// Service accounts must not be canonicalized to an email even if one is
	// somehow forwarded; their identifier is the SA path string.
	dyn := newFakeDynClient(
		// Add an unrelated User CR with email-as-name; resolveGroups must NOT
		// retry the SA lookup against this email.
		makeUser("ops@example.com", []string{"engineering"}),
		makeGroup("legacy", []string{"system:serviceaccount:ns:sa1"}),
	)

	canonical, groups := resolveGroups(t.Context(), dyn, "system:serviceaccount:ns:sa1", "ops@example.com", false)

	if canonical != "system:serviceaccount:ns:sa1" {
		t.Errorf("canonical = %q, want %q (SAs must not be canonicalized to an email)", canonical, "system:serviceaccount:ns:sa1")
	}
	if !slices.Equal(groups, []string{"legacy"}) {
		t.Errorf("groups = %v, want [legacy]", groups)
	}
}

func TestResolveGroups_NoMatchesReturnsEmpty(t *testing.T) {
	dyn := newFakeDynClient()

	canonical, groups := resolveGroups(t.Context(), dyn, "user1", "user1@gmail.com", false)

	if canonical != "user1" {
		t.Errorf("canonical = %q, want %q (no match should fall back to original)", canonical, "user1")
	}
	if groups != nil {
		t.Errorf("groups = %v, want nil", groups)
	}
}

func TestResolveGroups_NilDynClient_DevFallback(t *testing.T) {
	canonical, groups := resolveGroups(t.Context(), nil, "user1", "user1@gmail.com", true)

	if canonical != "user1" {
		t.Errorf("canonical = %q, want %q", canonical, "user1")
	}
	if !slices.Equal(groups, []string{"developers", "cluster-viewers"}) {
		t.Errorf("groups = %v, want dev fallback set", groups)
	}
}

func TestResolveGroups_NilDynClient_NoDev(t *testing.T) {
	canonical, groups := resolveGroups(t.Context(), nil, "user1", "user1@gmail.com", false)

	if canonical != "user1" {
		t.Errorf("canonical = %q, want %q", canonical, "user1")
	}
	if groups != nil {
		t.Errorf("groups = %v, want nil", groups)
	}
}

func TestResolveGroups_EmptyEmailDoesNotPanic(t *testing.T) {
	dyn := newFakeDynClient(
		makeGroup("team", []string{"user1"}),
	)

	canonical, groups := resolveGroups(t.Context(), dyn, "user1", "", false)
	if canonical != "user1" {
		t.Errorf("canonical = %q, want %q", canonical, "user1")
	}
	if !slices.Equal(groups, []string{"team"}) {
		t.Errorf("groups = %v, want [team]", groups)
	}
}

// countingDynClient wraps a fake dynamic client to count API calls per resource.
// Used to assert that resolveGroupsCached coalesces repeat lookups.
type countingDynClient struct {
	dynamic.Interface
	mu    sync.Mutex
	calls map[string]int
}

func (c *countingDynClient) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	c.mu.Lock()
	c.calls[gvr.Resource]++
	c.mu.Unlock()
	return c.Interface.Resource(gvr)
}

func (c *countingDynClient) count(resource string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[resource]
}

func newCountingDyn(objs ...*unstructured.Unstructured) *countingDynClient {
	return &countingDynClient{
		Interface: newFakeDynClient(objs...),
		calls:     map[string]int{},
	}
}

func TestResolveGroupsCached_CoalescesRepeatedCalls(t *testing.T) {
	dyn := newCountingDyn(
		makeUser("user1@gmail.com", nil),
		makeGroup("engineering", []string{"user1@gmail.com"}),
	)
	cache := newGroupCache(60 * time.Second)

	for i := range 4 {
		canonical, groups := resolveGroupsCached(t.Context(), cache, dyn, "user1", "user1@gmail.com", false)
		if canonical != "user1@gmail.com" {
			t.Fatalf("iter %d: canonical = %q, want user1@gmail.com", i, canonical)
		}
		if !slices.Equal(groups, []string{"engineering"}) {
			t.Fatalf("iter %d: groups = %v, want [engineering]", i, groups)
		}
	}

	// First call: looks up "user1" (404), then "user1@gmail.com" (hit, but groups null),
	// then lists groups once. So users=2, groups=1. Cached calls must add zero.
	if got := dyn.count("users"); got != 2 {
		t.Errorf("users API calls = %d, want 2 (only the first uncached request)", got)
	}
	if got := dyn.count("groups"); got != 1 {
		t.Errorf("groups API calls = %d, want 1", got)
	}
}

func TestResolveGroupsCached_CachesEmptyResult(t *testing.T) {
	dyn := newCountingDyn() // no Users, no Groups
	cache := newGroupCache(60 * time.Second)

	for range 3 {
		canonical, groups := resolveGroupsCached(t.Context(), cache, dyn, "ghost", "ghost@example.com", false)
		if canonical != "ghost" {
			t.Fatalf("canonical = %q, want ghost", canonical)
		}
		if groups != nil {
			t.Fatalf("groups = %v, want nil", groups)
		}
	}

	if got := dyn.count("users"); got != 2 {
		t.Errorf("users API calls = %d, want 2 (one per candidate, only on first call)", got)
	}
	if got := dyn.count("groups"); got != 1 {
		t.Errorf("groups API calls = %d, want 1", got)
	}
}

func TestResolveGroupsCached_DistinctPrincipalsBypassEachOther(t *testing.T) {
	dyn := newCountingDyn(
		makeUser("alice@example.com", []string{"team-a"}),
		makeUser("bob@example.com", []string{"team-b"}),
	)
	cache := newGroupCache(60 * time.Second)

	_, gA := resolveGroupsCached(t.Context(), cache, dyn, "alice", "alice@example.com", false)
	_, gB := resolveGroupsCached(t.Context(), cache, dyn, "bob", "bob@example.com", false)
	_, gA2 := resolveGroupsCached(t.Context(), cache, dyn, "alice", "alice@example.com", false)

	if !slices.Equal(gA, []string{"team-a"}) || !slices.Equal(gA2, []string{"team-a"}) {
		t.Errorf("alice groups = %v / %v", gA, gA2)
	}
	if !slices.Equal(gB, []string{"team-b"}) {
		t.Errorf("bob groups = %v", gB)
	}

	// alice 1st call: 2 user lookups (404, hit). bob 1st call: same. alice 2nd: cached.
	if got := dyn.count("users"); got != 4 {
		t.Errorf("users API calls = %d, want 4", got)
	}
}

func TestResolveGroupsCached_TTLExpiry(t *testing.T) {
	dyn := newCountingDyn(
		makeUser("user1@gmail.com", []string{"engineering"}),
	)
	cache := newGroupCache(60 * time.Second)

	resolveGroupsCached(t.Context(), cache, dyn, "user1", "user1@gmail.com", false)
	if got := dyn.count("users"); got != 2 {
		t.Fatalf("after first call: users = %d, want 2", got)
	}

	// Force expiry by mutating the entry's expiresAt.
	cache.mu.Lock()
	for k, v := range cache.entries {
		v.expiresAt = time.Now().Add(-1 * time.Second)
		cache.entries[k] = v
	}
	cache.mu.Unlock()

	resolveGroupsCached(t.Context(), cache, dyn, "user1", "user1@gmail.com", false)
	if got := dyn.count("users"); got != 4 {
		t.Errorf("after expiry: users = %d, want 4 (cache miss should re-query)", got)
	}
}

func TestResolveGroupsCached_NilCacheBypasses(t *testing.T) {
	dyn := newCountingDyn(
		makeUser("alice", []string{"team-a"}),
	)

	// ttl <= 0 → newGroupCache returns nil; wrapper must not panic and must
	// fall through to resolveGroups on every call.
	cache := newGroupCache(0)
	if cache != nil {
		t.Fatalf("newGroupCache(0) should return nil")
	}

	for range 3 {
		resolveGroupsCached(t.Context(), cache, dyn, "alice", "", false)
	}
	if got := dyn.count("users"); got != 3 {
		t.Errorf("users API calls = %d, want 3 (every call uncached)", got)
	}
}
