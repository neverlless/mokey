package server

import (
	"net/url"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/storage/memory/v2"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testFAConfig() *forwardAuthConfig {
	return &forwardAuthConfig{SessionIdle: 8 * time.Hour, SessionMax: 24 * time.Hour, Recheck: 2 * time.Minute}
}

func faRouter() *Router {
	r := lockedRouter(memory.New())
	r.forwardAuth = testFAConfig()
	return r
}

func TestFAPendingSingleUse(t *testing.T) {
	r := faRouter()
	rd, _ := url.Parse("https://app.example.com/x?y=1")
	id, nonce, err := r.faNewPending(rd, "app.example.com")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(id), 43)
	assert.GreaterOrEqual(t, len(nonce), 43)

	p, err := r.faTakePending(id)
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, rd.String(), p.RD)
	assert.Equal(t, "app.example.com", p.Host)
	assert.Equal(t, nonce, p.Nonce)

	p, err = r.faTakePending(id)
	assert.NoError(t, err)
	assert.Nil(t, p)
}

func TestFACodeSingleUse(t *testing.T) {
	r := faRouter()
	in := faCode{Username: "walter", Host: "app.example.com", PendingID: "p1", ParentSID: "s1"}
	code, err := r.faNewCode(in)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(code), 43)

	got, err := r.faTakeCode(code)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, in, *got)

	got, err = r.faTakeCode(code)
	assert.NoError(t, err)
	assert.Nil(t, got)

	got, err = r.faTakeCode("")
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestFACodeExpires(t *testing.T) {
	st := memory.New()
	r := lockedRouter(st)
	r.forwardAuth = testFAConfig()
	code, err := r.faNewCode(faCode{Username: "walter"})
	require.NoError(t, err)

	// the stored TTL is what expires the code; prove it is 60s by replacing
	// the entry with an already-expired one of the same key
	raw, _ := st.Get(faCodePrefix + code)
	require.NotNil(t, raw)
	require.NoError(t, st.Set(faCodePrefix+code, raw, time.Nanosecond))
	time.Sleep(1100 * time.Millisecond)
	got, err := r.faTakeCode(code)
	assert.NoError(t, err)
	assert.Nil(t, got)
	assert.Equal(t, 60*time.Second, faCodeTTL)
	assert.Equal(t, 10*time.Minute, faPendingTTL)
}

func newFASession(t *testing.T, r *Router, user, parent string) *faSession {
	t.Helper()
	s := &faSession{Username: user, Host: "app.example.com", ParentSID: parent, Groups: []string{"ipausers"}, Name: "Walter White", Email: "w@example.com"}
	require.NoError(t, r.faCreateSession(s))
	require.GreaterOrEqual(t, len(s.ID), 43)
	return s
}

func faAlive(t *testing.T, r *Router, id string) bool {
	t.Helper()
	s, err := r.faLoadSession(id)
	require.NoError(t, err)
	return s != nil
}

func TestFASessionLifecycle(t *testing.T) {
	r := faRouter()
	s := newFASession(t, r, "walter", "sid1")

	got, err := r.faLoadSession(s.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "walter", got.Username)
	assert.Equal(t, []string{"ipausers"}, got.Groups)
	assert.False(t, got.Created.IsZero())

	require.NoError(t, r.faDeleteSession(s.ID))
	assert.False(t, faAlive(t, r, s.ID))

	got, err = r.faLoadSession("nope")
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestFASessionIdleAndMax(t *testing.T) {
	r := faRouter()
	s := newFASession(t, r, "walter", "sid1")
	s.LastSeen = time.Now().Add(-9 * time.Hour)
	s.CheckedAt = s.LastSeen
	require.NoError(t, r.faSave(s))
	assert.False(t, faAlive(t, r, s.ID), "idle session must not load")

	s = newFASession(t, r, "walter", "sid1")
	s.Created = time.Now().Add(-25 * time.Hour)
	require.NoError(t, r.faSave(s))
	assert.False(t, faAlive(t, r, s.ID), "session past max must not load")
}

func TestFATouchThrottled(t *testing.T) {
	r := faRouter()
	s := newFASession(t, r, "walter", "sid1")
	seen := s.LastSeen

	require.NoError(t, r.faTouch(s))
	got, _ := r.faLoadSession(s.ID)
	assert.True(t, got.LastSeen.Equal(seen), "no write within a minute")

	s.LastSeen = time.Now().Add(-2 * time.Minute)
	require.NoError(t, r.faTouch(s))
	got, _ = r.faLoadSession(s.ID)
	assert.True(t, got.LastSeen.After(seen.Add(-time.Second)))
	assert.WithinDuration(t, time.Now(), got.LastSeen, 5*time.Second)

	// a fresh recheck is written even within the minute
	s = got
	s.CheckedAt = time.Now().Add(time.Second)
	require.NoError(t, r.faTouch(s))
	got, _ = r.faLoadSession(s.ID)
	assert.True(t, got.CheckedAt.Equal(s.CheckedAt))
}

func TestFATouchDoesNotResurrect(t *testing.T) {
	r := faRouter()
	s := newFASession(t, r, "walter", "sid1")
	r.faRevokeUser("walter")
	s.LastSeen = time.Now().Add(-2 * time.Minute)
	_ = r.faTouch(s)
	assert.False(t, faAlive(t, r, s.ID))
}

func TestFARevoke(t *testing.T) {
	r := faRouter()
	a1 := newFASession(t, r, "walter", "sid1")
	a2 := newFASession(t, r, "walter", "sid1")
	b := newFASession(t, r, "walter", "sid2")
	j := newFASession(t, r, "jesse", "sid3")

	r.faRevokeParent("walter", "sid1")
	assert.False(t, faAlive(t, r, a1.ID))
	assert.False(t, faAlive(t, r, a2.ID))
	assert.True(t, faAlive(t, r, b.ID))

	// a parent sid of another user is ignored
	r.faRevokeParent("walter", "sid3")
	assert.True(t, faAlive(t, r, j.ID))

	r.faRevokeUser("walter")
	assert.False(t, faAlive(t, r, b.ID))
	assert.True(t, faAlive(t, r, j.ID))
}

func TestFARevokeDisabledFeatureSkipsStorage(t *testing.T) {
	r := &Router{} // nil forwardAuth; any storage call would panic
	r.faRevokeUser("walter")
	r.faRevokeParent("walter", "sid1")
	r.faRevokeOtherParents("walter", "sid1")
}

// hook tests: two mokey sessions for walter, app sessions under each

func faHookSetup(t *testing.T, configure func()) (*fiber.App, *Router, *testClient, *testClient, *faSession, *faSession, *faSession) {
	t.Helper()
	app, r, fake := newTestAppWith(t, configure)
	r.forwardAuth = testFAConfig()
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	fake.AddUser("jesse", ipatest.User{Password: "Secret123!", Groups: []string{"admins"}})

	tc1 := newTestClient(t, app)
	tc1.login("walter", "Secret123!")
	tc2 := newTestClient(t, app)
	tc2.login("walter", "Secret123!")
	idx := r.loadSessionIndex("walter")
	require.Len(t, idx, 2)
	s1 := newFASession(t, r, "walter", idx[0].SID)
	s2 := newFASession(t, r, "walter", idx[1].SID)
	other := newFASession(t, r, "jesse", "jesse-sid")
	return app, r, tc1, tc2, s1, s2, other
}

func TestFAHookLogout(t *testing.T) {
	_, r, tc1, _, s1, s2, _ := faHookSetup(t, nil)
	resp := tc1.postForm("/auth/logout", url.Values{}, nil)
	assert.Equal(t, fiber.StatusFound, resp.StatusCode)
	assert.False(t, faAlive(t, r, s1.ID))
	assert.True(t, faAlive(t, r, s2.ID))
}

func TestFAHookRevokeOne(t *testing.T) {
	_, r, tc1, _, s1, s2, _ := faHookSetup(t, nil)
	resp := tc1.postForm("/security/session/revoke", url.Values{"sid": {s2.ParentSID}}, htmx)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.False(t, faAlive(t, r, s2.ID))
	assert.True(t, faAlive(t, r, s1.ID))
}

func TestFAHookRevokeOthers(t *testing.T) {
	_, r, tc1, _, s1, s2, other := faHookSetup(t, nil)
	orphan := newFASession(t, r, "walter", "sid-not-in-index")
	resp := tc1.postForm("/security/sessions/revoke-others", url.Values{}, htmx)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.False(t, faAlive(t, r, s2.ID))
	assert.False(t, faAlive(t, r, orphan.ID))
	assert.True(t, faAlive(t, r, s1.ID))
	assert.True(t, faAlive(t, r, other.ID))
}

func TestFAHookPasswordChange(t *testing.T) {
	_, r, tc1, _, s1, s2, other := faHookSetup(t, nil)
	resp := tc1.postForm("/password/change", url.Values{
		"password":     {"Secret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
	}, htmx)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.False(t, faAlive(t, r, s1.ID))
	assert.False(t, faAlive(t, r, s2.ID))
	assert.True(t, faAlive(t, r, other.ID))
}

func TestFAHookAdminBlock(t *testing.T) {
	app, r, _, _, s1, s2, _ := faHookSetup(t, func() { viper.Set("admin.enabled", true) })
	admin := newTestClient(t, app)
	admin.login("jesse", "Secret123!")
	resp := admin.postForm("/admin/user/block", url.Values{"username": {"walter"}}, htmx)
	assert.NotEqual(t, fiber.StatusForbidden, resp.StatusCode)
	assert.False(t, faAlive(t, r, s1.ID))
	assert.False(t, faAlive(t, r, s2.ID))
}
