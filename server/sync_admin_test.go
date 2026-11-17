package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncAdminApp signs in skyler, an admin. No default or mapped group
// members: group writes as the service account fail the test harness.
func syncAdminApp(t *testing.T) (*testClient, *Router, *ipatest.Server, *fakeSyncSource) {
	t.Helper()
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
		viper.Set("admin.group", "admins")
		viper.Set("accounts.enable_captcha", false)
	})
	router.sync = &syncConfig{
		ManagedGroup:      "google2ipa-managed",
		GroupMapping:      map[string][]string{"eng@example.org": {"eng"}},
		Username:          "local_part",
		MaxUsernameLength: 32,
		Concurrency:       4,
		MaxEventsPerRun:   50,
		MaxDisablePercent: 20,
		Disable:           true,
		Preserve:          true,
		Google:            googleSourceConfig{Domains: []string{"example.org"}},
	}
	src := &fakeSyncSource{}
	router.syncSrc = src
	fake.AddGroup("google2ipa-managed", ipatest.Group{})
	fake.AddGroup("eng", ipatest.Group{})
	fake.AddUser("skyler", ipatest.User{Password: spSecret, Groups: []string{"admins"}})
	fake.AddUser("jesse", ipatest.User{Password: spSecret})

	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(NewAuditHandler(slog.NewTextHandler(&logs, nil), router.storage)))
	t.Cleanup(func() { slog.SetDefault(saved) })

	tc := newTestClient(t, app)
	tc.login("skyler", spSecret)
	return tc, router, fake, src
}

// syncBrakeHeld: ten managed accounts, five gone from Google, held by the brake.
func syncBrakeHeld(t *testing.T, router *Router, fake *ipatest.Server, src *fakeSyncSource) {
	t.Helper()
	var uids []string
	for i := range 10 {
		uids = append(uids, fmt.Sprintf("user%d", i))
	}
	managed(fake, uids...)
	src.users = nil
	for _, uid := range uids[:5] {
		src.users = append(src.users, googleUser(uid))
	}
	res, ran, err := router.syncRunLocked(t.Context(), time.Now(), "", false)
	require.NoError(t, err)
	require.True(t, ran)
	require.True(t, res.Held)
	require.Equal(t, 5, res.HeldCount)
}

func storeSyncResult(t *testing.T, router *Router, key string, res syncRunResult) {
	t.Helper()
	b, err := json.Marshal(res)
	require.NoError(t, err)
	require.NoError(t, router.storage.Set(key, b, 0))
}

func selectedTab(t *testing.T, body string) string {
	t.Helper()
	for _, tab := range []string{"held", "decisions", "last", "settings"} {
		if bytes.Contains([]byte(body), []byte(`href="/admin/sync?tab=`+tab+`" aria-selected="true"`)) {
			return tab
		}
	}
	return ""
}

func TestAdminSyncOff(t *testing.T) {
	tc, router, _, _ := syncAdminApp(t)
	router.sync = nil

	assert.NotContains(t, readBody(t, tc.get("/admin/people")), `href="/admin/sync"`)
	assert.Equal(t, fiber.StatusNotFound, tc.get("/admin/sync").StatusCode)
	assert.Equal(t, fiber.StatusNotFound, tc.get("/admin/sync/status", htmx).StatusCode)
	for _, p := range []string{"/admin/sync/dry-run", "/admin/sync/apply", "/admin/sync/import-legacy"} {
		assert.Equal(t, fiber.StatusNotFound, tc.postForm(p, nil, htmx).StatusCode, p)
	}
}

func TestAdminSyncNonAdmin(t *testing.T) {
	tc, _, fake, _ := syncAdminApp(t)
	jt := newTestClient(t, tc.app)
	jt.login("jesse", spSecret)

	assert.Equal(t, fiber.StatusForbidden, jt.get("/admin/sync").StatusCode)
	assert.Equal(t, fiber.StatusForbidden, jt.get("/admin/sync/status", htmx).StatusCode)
	for _, p := range []string{"/admin/sync/dry-run", "/admin/sync/apply", "/admin/sync/import-legacy"} {
		assert.Equal(t, fiber.StatusForbidden, jt.postForm(p, nil, htmx).StatusCode, p)
	}
	assert.Empty(t, writeCalls(fake))
}

func TestAdminSyncDefaultTab(t *testing.T) {
	tc, router, _, _ := syncAdminApp(t)

	page := readBody(t, tc.get("/admin/sync"))
	assert.Contains(t, page, `href="/admin/sync" aria-current="page"`)
	assert.Contains(t, page, T("sync.admin_never"))
	assert.Equal(t, "last", selectedTab(t, page))
	assert.Contains(t, page, esc(T("sync.admin_manual_only")))

	storeSyncResult(t, router, syncLastKey, syncRunResult{
		At: time.Now(), Applied: map[string]int{"create": 2, "group_add": 3, "group_remove": 1},
		Plan:        syncPlan{Conflicts: []string{"uid jdoe belongs to a@x in FreeIPA but to jdoe@example.org in Google; left alone"}, BackInGoogle: []string{"kwalsh"}},
		SkipReasons: []string{"skip uid \"obrien\": derived from several Google users"},
	})
	page = readBody(t, tc.get("/admin/sync"))
	assert.Equal(t, "decisions", selectedTab(t, page))
	assert.Contains(t, page, esc(T("sync.admin_tab_decisions"))+" · 3")
	assert.Contains(t, page, "uid jdoe belongs to")
	assert.Contains(t, page, `href="/admin/people?search=kwalsh"`)

	storeSyncResult(t, router, syncHeldKey, syncRunResult{At: time.Now(), Held: true, HeldCount: 7, Plan: syncPlan{Disable: []string{"rmiller"}}})
	page = readBody(t, tc.get("/admin/sync"))
	assert.Equal(t, "held", selectedTab(t, page))
	assert.Contains(t, page, ">rmiller<")
	assert.Contains(t, page, `name="expected" value="7"`)

	// an explicit tab wins, from the page and from the htmx pane
	assert.Equal(t, "settings", selectedTab(t, readBody(t, tc.get("/admin/sync?tab=settings"))))
	assert.Equal(t, "last", selectedTab(t, readBody(t, tc.get("/admin/sync/status?tab=last", htmx))))
	assert.Equal(t, "held", selectedTab(t, readBody(t, tc.get("/admin/sync?tab=bogus"))))
}

func TestAdminSyncApplyLiftsBrake(t *testing.T) {
	tc, router, fake, src := syncAdminApp(t)
	syncBrakeHeld(t, router, fake, src)
	for i := 5; i < 10; i++ {
		require.False(t, locked(fake, fmt.Sprintf("user%d", i)))
	}

	body := readBody(t, tc.postForm("/admin/sync/apply", url.Values{"expected": {"5"}}, htmx))
	assert.Equal(t, "last", selectedTab(t, body))
	for i := 5; i < 10; i++ {
		assert.True(t, locked(fake, fmt.Sprintf("user%d", i)))
	}
	last, err := router.syncLastRun()
	require.NoError(t, err)
	assert.Equal(t, "skyler", last.By)
	assert.Equal(t, 5, last.Applied["disable"])
	held, err := router.syncHeld()
	require.NoError(t, err)
	assert.Nil(t, held)
	if ev := auditEvents(router, "sync user disabled"); assert.Len(t, ev, 5) {
		assert.Equal(t, "skyler", ev[0].Actor)
	}
}

func TestAdminSyncApplyRefusedWhenPlanGrew(t *testing.T) {
	tc, router, fake, src := syncAdminApp(t)
	syncBrakeHeld(t, router, fake, src)
	src.users = src.users[:4]

	body := readBody(t, tc.postForm("/admin/sync/apply", url.Values{"expected": {"5"}}, htmx))
	assert.Contains(t, body, esc(T("sync.admin_plan_changed")))
	assert.Equal(t, "held", selectedTab(t, body))
	assert.Contains(t, body, `name="expected" value="6"`)
	for i := 4; i < 10; i++ {
		assert.False(t, locked(fake, fmt.Sprintf("user%d", i)))
	}
	last, err := router.syncLastRun()
	require.NoError(t, err)
	assert.Empty(t, last.By)

	// a missing count is zero, never "anything goes"
	readBody(t, tc.postForm("/admin/sync/apply", nil, htmx))
	assert.False(t, locked(fake, "user9"))
}

func TestAdminSyncDryRun(t *testing.T) {
	tc, router, fake, src := syncAdminApp(t)
	syncBrakeHeld(t, router, fake, src)
	before := len(writeCalls(fake))

	body := readBody(t, tc.postForm("/admin/sync/dry-run", nil, htmx))
	assert.Contains(t, body, esc(T("sync.admin_dry_banner")))
	assert.Equal(t, "last", selectedTab(t, body))
	assert.Contains(t, body, ">user9<")
	assert.Equal(t, before, len(writeCalls(fake)))
}

func TestAdminSyncClaimHeld(t *testing.T) {
	tc, router, fake, src := syncAdminApp(t)
	syncBrakeHeld(t, router, fake, src)
	release, ok, err := router.lock.claim(syncRunKey, syncRunTTL)
	require.NoError(t, err)
	require.True(t, ok)
	defer release()

	for _, p := range []string{"/admin/sync/dry-run", "/admin/sync/apply"} {
		body := readBody(t, tc.postForm(p, url.Values{"expected": {"5"}}, htmx))
		assert.Contains(t, body, esc(T("sync.admin_busy")), p)
	}
	assert.False(t, locked(fake, "user9"))
}

func TestAdminSyncImportLegacyOnce(t *testing.T) {
	tc, router, fake, _ := syncAdminApp(t)
	router.sync.ImportLegacyLocks = true
	now := time.Now()
	lockedAt := now.Add(-30 * 24 * time.Hour).Truncate(time.Second)
	foundAt := now.Add(-60 * 24 * time.Hour).Truncate(time.Second)
	fake.AddUser("gale", ipatest.User{Locked: true, PrincipalExpire: lockedAt})
	fake.AddUser("jane", ipatest.User{Locked: true, PrincipalExpire: lockedAt})
	fake.AddUser("hank", ipatest.User{Locked: true})                            // admin block, no expiry
	fake.AddUser("pete", ipatest.User{Locked: true, PrincipalExpire: lockedAt}) // a sync lock already
	fake.AddUser("todd", ipatest.User{Locked: true, PrincipalExpire: lockedAt}) // not managed
	fake.AddGroup("google2ipa-managed", ipatest.Group{Members: []string{"gale", "jane", "hank", "pete"}})
	require.NoError(t, router.syncSetMarker("jane", syncMarker{Kind: syncMarkerFound, At: foundAt, By: "sync"}))
	require.NoError(t, router.syncSetMarker("pete", syncMarker{Kind: syncMarkerSync, At: now, By: "sync"}))

	body := readBody(t, tc.get("/admin/sync?tab=decisions"))
	assert.Contains(t, body, ">gale<")
	assert.Contains(t, body, ">jane<")
	for _, uid := range []string{"hank", "pete", "todd"} {
		assert.NotContains(t, body, ">"+uid+"<")
	}
	assert.Contains(t, body, `hx-post="/admin/sync/import-legacy"`)
	assert.Contains(t, body, "hx-confirm=")

	body = readBody(t, tc.postForm("/admin/sync/import-legacy", nil, htmx))
	assert.Contains(t, body, esc(fmt.Sprintf(T("sync.admin_imported"), 2)))
	m, err := router.syncGetMarker("gale")
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, syncMarkerLegacy, m.Kind)
	assert.True(t, lockedAt.Equal(m.At), m.At)
	assert.Equal(t, "skyler", m.By)
	m, err = router.syncGetMarker("jane")
	require.NoError(t, err)
	assert.Equal(t, syncMarkerLegacy, m.Kind)
	assert.True(t, foundAt.Equal(m.At), m.At)
	m, err = router.syncGetMarker("hank")
	require.NoError(t, err)
	assert.Nil(t, m)
	assert.NotContains(t, body, `hx-post="/admin/sync/import-legacy"`)

	// once only: a candidate that shows up later is never imported
	fake.AddUser("lydia", ipatest.User{Locked: true, PrincipalExpire: lockedAt})
	fake.AddGroup("google2ipa-managed", ipatest.Group{Members: []string{"gale", "jane", "hank", "pete", "lydia"}})
	resp := tc.postForm("/admin/sync/import-legacy", nil, htmx)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode, strconv.Itoa(resp.StatusCode))
	m, err = router.syncGetMarker("lydia")
	require.NoError(t, err)
	assert.Nil(t, m)
	assert.NotContains(t, readBody(t, tc.get("/admin/sync?tab=decisions")), ">lydia<")
}
