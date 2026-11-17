package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/storage/memory/v2"
	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func syncTargetRouter(t *testing.T) (*Router, *ipatest.Server, *syncConfig) {
	t.Helper()
	fake := ipatest.NewServer(t)
	fake.AddGroup("google2ipa-managed", ipatest.Group{})
	fake.AddGroup("staff", ipatest.Group{})
	fake.AddGroup("eng", ipatest.Group{})
	cfg := &syncConfig{
		ManagedGroup:  "google2ipa-managed",
		DefaultGroups: []string{"staff"},
		GroupMapping:  map[string][]string{"eng@example.org": {"eng"}},
	}
	return &Router{adminClient: fake.ClientAs("admin"), storage: memory.New()}, fake, cfg
}

func TestSyncTargetCreateNoPassword(t *testing.T) {
	r, fake, cfg := syncTargetRouter(t)
	u := syncUser{UID: "jesse", syncSourceUser: syncSourceUser{Email: "jesse@example.org", GivenName: "Jesse", FamilyName: "Pinkman", FullName: "Jesse Pinkman"}}
	require.NoError(t, r.syncCreate(u, cfg))

	got, ok := fake.User("jesse")
	require.True(t, ok)
	assert.Empty(t, got.Password)
	assert.Equal(t, "jesse@example.org", got.Email)
	assert.Equal(t, "Jesse Pinkman", got.DisplayName)
	for _, c := range fake.Calls() {
		if c.Method == "user_add" {
			assert.NotContains(t, c.Options, "random")
			assert.NotContains(t, c.Options, "userpassword")
		}
	}
	for _, g := range []string{"google2ipa-managed", "staff"} {
		grp, _ := fake.Group(g)
		assert.Contains(t, grp.Members, "jesse", g)
	}
}

func TestSyncTargetUpdate(t *testing.T) {
	r, fake, _ := syncTargetRouter(t)
	fake.AddUser("jesse", ipatest.User{Email: "old@example.org", First: "J", Last: "P"})
	require.NoError(t, r.syncUpdate(syncUpdate{UID: "jesse", To: syncSourceUser{Email: "jesse@example.org", GivenName: "Jesse", FamilyName: "Pinkman", FullName: "Jesse Pinkman"}}))
	got, _ := fake.User("jesse")
	assert.Equal(t, []string{"jesse@example.org", "Jesse", "Pinkman", "Jesse Pinkman"}, []string{got.Email, got.First, got.Last, got.DisplayName})
}

func TestSyncTargetGroupsIdempotent(t *testing.T) {
	r, fake, _ := syncTargetRouter(t)
	fake.AddUser("jesse", ipatest.User{})
	fake.AddGroup("staff", ipatest.Group{Members: []string{"jesse"}})
	require.NoError(t, r.syncGroups("jesse", []string{"staff", "eng"}, nil))
	require.NoError(t, r.syncGroups("jesse", nil, []string{"eng", "eng"}))
	g, _ := fake.Group("eng")
	assert.NotContains(t, g.Members, "jesse")
}

func TestSyncTargetDisableWritesMarker(t *testing.T) {
	r, fake, _ := syncTargetRouter(t)
	fake.AddUser("jesse", ipatest.User{})
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	require.NoError(t, r.syncDisable("jesse", now, "sync"))
	got, _ := fake.User("jesse")
	assert.True(t, got.Locked)
	m, err := r.syncGetMarker("jesse")
	require.NoError(t, err)
	assert.Equal(t, &syncMarker{Kind: syncMarkerSync, At: now, By: "sync"}, m)
}

func TestSyncTargetDisableMarkerBeforeLock(t *testing.T) {
	r, fake, _ := syncTargetRouter(t)
	fake.AddUser("jesse", ipatest.User{})
	r.storage = &failingSetStorage{r.storage}
	assert.Error(t, r.syncDisable("jesse", time.Now(), "sync"))
	got, _ := fake.User("jesse")
	assert.False(t, got.Locked, "no lock without a marker")
}

func TestSyncTargetDisableFailureKeepsMarker(t *testing.T) {
	r, _, _ := syncTargetRouter(t)
	assert.Error(t, r.syncDisable("ghost", time.Now(), "sync"))
	m, err := r.syncGetMarker("ghost")
	require.NoError(t, err)
	assert.NotNil(t, m, "left for ClearMarkers on the next run")
}

func TestSyncTargetEnableLegacyClearsExpiry(t *testing.T) {
	r, fake, _ := syncTargetRouter(t)
	fake.AddUser("jesse", ipatest.User{Locked: true, PrincipalExpire: time.Now().Add(-time.Hour)})
	m := syncMarker{Kind: syncMarkerLegacy, At: time.Now(), By: "import"}
	require.NoError(t, r.syncSetMarker("jesse", m))
	require.NoError(t, r.syncEnable("jesse", m))
	got, _ := fake.User("jesse")
	assert.False(t, got.Locked)
	assert.True(t, got.PrincipalExpire.IsZero())
	mk, err := r.syncGetMarker("jesse")
	require.NoError(t, err)
	assert.Nil(t, mk)
}

func TestSyncTargetEnableSyncKeepsExpiry(t *testing.T) {
	r, fake, _ := syncTargetRouter(t)
	exp := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	fake.AddUser("jesse", ipatest.User{Locked: true, PrincipalExpire: exp})
	m := syncMarker{Kind: syncMarkerSync, At: time.Now(), By: "sync"}
	require.NoError(t, r.syncSetMarker("jesse", m))
	require.NoError(t, r.syncEnable("jesse", m))
	got, _ := fake.User("jesse")
	assert.False(t, got.Locked)
	assert.True(t, exp.Equal(got.PrincipalExpire))
	for _, c := range fake.Calls() {
		assert.NotContains(t, c.Options, "krbprincipalexpiration")
	}
}

func TestSyncTargetEnableMarkerDeleteFails(t *testing.T) {
	r, fake, _ := syncTargetRouter(t)
	fake.AddUser("jesse", ipatest.User{Locked: true})
	r.storage = &failingDeleteStorage{r.storage}
	assert.Error(t, r.syncEnable("jesse", syncMarker{Kind: syncMarkerSync}))
}

func TestSyncTargetClearMissingMarker(t *testing.T) {
	r, _, _ := syncTargetRouter(t)
	assert.NoError(t, r.syncClearMarker("nobody"))
}

func TestSyncTargetDeletePreserve(t *testing.T) {
	r, fake, _ := syncTargetRouter(t)
	fake.AddUser("jesse", ipatest.User{Locked: true})
	fake.AddUser("walt", ipatest.User{Locked: true})
	for _, uid := range []string{"jesse", "walt"} {
		require.NoError(t, r.syncSetMarker(uid, syncMarker{Kind: syncMarkerSync}))
	}
	require.NoError(t, r.syncDelete("jesse", true))
	require.NoError(t, r.syncDelete("walt", false))
	got, ok := fake.User("jesse")
	require.True(t, ok)
	assert.True(t, got.Preserved)
	_, ok = fake.User("walt")
	assert.False(t, ok)
	for _, uid := range []string{"jesse", "walt"} {
		m, err := r.syncGetMarker(uid)
		require.NoError(t, err)
		assert.Nil(t, m)
	}
}

func TestSyncTargetLoad(t *testing.T) {
	r, fake, cfg := syncTargetRouter(t)
	now := time.Now()
	fake.AddUser("jesse", ipatest.User{Email: "jesse@example.org", First: "Jesse", Last: "Pinkman", DisplayName: "Jesse Pinkman"})
	fake.AddUser("walt", ipatest.User{Locked: true, PrincipalExpire: now.Add(-time.Hour)})
	fake.AddUser("skyler", ipatest.User{PrincipalExpire: now.Add(time.Hour)})
	fake.AddUser("hank", ipatest.User{})  // not managed, requested
	fake.AddUser("marie", ipatest.User{}) // not managed, not requested
	fake.AddUser("gus", ipatest.User{Preserved: true, Locked: true})
	fake.AddGroup("google2ipa-managed", ipatest.Group{Members: []string{"jesse", "walt", "skyler"}})
	fake.AddGroup("staff", ipatest.Group{Members: []string{"jesse", "hank"}})
	fake.AddGroup("other", ipatest.Group{Members: []string{"jesse"}})
	fake.AddGroup("eng", ipatest.Group{MemberGroups: []string{"other"}})
	m := syncMarker{Kind: syncMarkerSync, At: now.Add(-time.Hour).UTC().Truncate(time.Second), By: "sync"}
	require.NoError(t, r.syncSetMarker("walt", m))

	got, err := r.syncLoadIPA(context.Background(), cfg, []string{"hank", "gus", "nobody"}, now)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"jesse", "walt", "skyler", "hank", "gus"}, keys(got))

	j := got["jesse"]
	assert.Equal(t, syncIPAUser{UID: "jesse", Email: "jesse@example.org", GivenName: "Jesse", FamilyName: "Pinkman", FullName: "Jesse Pinkman", Managed: true, Groups: []string{"google2ipa-managed", "staff"}}, j, "indirect and unrelated groups left out")
	assert.True(t, got["walt"].Locked)
	assert.True(t, got["walt"].Expired)
	require.NotNil(t, got["walt"].Marker)
	assert.True(t, m.At.Equal(got["walt"].Marker.At))
	assert.Equal(t, syncMarkerSync, got["walt"].Marker.Kind)
	assert.False(t, got["skyler"].Expired)
	assert.False(t, got["hank"].Managed)
	assert.Equal(t, []string{"staff"}, got["hank"].Groups)
	assert.True(t, got["gus"].Preserved)
}

func TestSyncTargetTruncatedAborts(t *testing.T) {
	r, fake, cfg := syncTargetRouter(t)
	fake.Handle("user_find", func(c ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": []map[string]any{{"uid": []string{"jesse"}}}, "count": 1, "truncated": true, "summary": "1 entry returned"}, nil
	})
	_, err := r.syncLoadIPA(context.Background(), cfg, nil, time.Now())
	assert.True(t, errors.Is(err, ipa.ErrTruncated), "got %v", err)
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type failingDeleteStorage struct{ fiber.Storage }

func (s *failingDeleteStorage) Delete(string) error { return errors.New("storage down") }
