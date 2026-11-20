package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
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
		Plan:        syncPlan{Conflicts: []string{"uid jdoe belongs to a@x in FreeIPA but to jdoe@example.org in Google; left alone"}, BackInGoogle: []string{"kwalsh"}, Skipped: []string{"obrien"}},
		SkipReasons: []string{"skip uid \"obrien\": derived from several Google users"},
	})
	page = readBody(t, tc.get("/admin/sync"))
	assert.Equal(t, "decisions", selectedTab(t, page))
	assert.Contains(t, page, esc(T("sync.admin_tab_decisions"))+" · 3")
	// the row shows the uid already
	assert.Contains(t, page, "· belongs to a@x in FreeIPA")
	assert.Contains(t, page, "· derived from several Google users")
	assert.NotContains(t, page, "uid jdoe")
	assert.NotContains(t, page, "skip uid")
	for _, uid := range []string{"jdoe", "obrien", "kwalsh"} {
		assert.Contains(t, page, `<span class="mokey-mono">`+uid+`</span>`)
	}
	assert.Contains(t, page, `href="/admin/people?search=kwalsh"`)

	storeSyncResult(t, router, syncHeldKey, syncRunResult{At: time.Now(), Held: true, HeldCount: 7, HeldDisable: 6, HeldDelete: 1, Plan: syncPlan{Disable: []string{"rmiller"}}})
	page = readBody(t, tc.get("/admin/sync"))
	assert.Equal(t, "held", selectedTab(t, page))
	assert.Contains(t, page, ">rmiller<")
	assert.Contains(t, page, `name="disable" value="6"`)
	assert.Contains(t, page, `name="delete" value="1"`)

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

	body := readBody(t, tc.postForm("/admin/sync/apply", url.Values{"disable": {"5"}, "delete": {"0"}}, htmx))
	assert.Equal(t, "last", selectedTab(t, body))
	router.bg.Wait()
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
	assert.NotContains(t, readBody(t, tc.get("/admin/sync/status", htmx)), esc(T("sync.admin_running_hint")))
	if ev := auditEvents(router, "sync user disabled"); assert.Len(t, ev, 5) {
		assert.Equal(t, "skyler", ev[0].Actor)
	}
}

func TestAdminSyncApplyRefusedWhenPlanGrew(t *testing.T) {
	tc, router, fake, src := syncAdminApp(t)
	syncBrakeHeld(t, router, fake, src)
	src.users = src.users[:4]

	body := readBody(t, tc.postForm("/admin/sync/apply", url.Values{"disable": {"5"}, "delete": {"0"}}, htmx))
	router.bg.Wait()
	assert.Contains(t, body, esc(T("sync.admin_plan_changed")))
	assert.Equal(t, "held", selectedTab(t, body))
	assert.Contains(t, body, `name="disable" value="6"`)
	held, err := router.syncHeld()
	require.NoError(t, err)
	assert.Equal(t, 6, held.HeldDisable)
	assert.Equal(t, "skyler", held.By)
	assert.Contains(t, readBody(t, tc.get("/admin/sync")), `name="disable" value="6"`)
	for i := 4; i < 10; i++ {
		assert.False(t, locked(fake, fmt.Sprintf("user%d", i)))
	}
	last, err := router.syncLastRun()
	require.NoError(t, err)
	assert.Empty(t, last.By)

	// a missing count is zero, never "anything goes"
	readBody(t, tc.postForm("/admin/sync/apply", nil, htmx))
	router.bg.Wait()
	assert.False(t, locked(fake, "user9"))
}

// fewer locks but a new delete: the same total must not pass
func TestAdminSyncApplyRefusedNewDelete(t *testing.T) {
	tc, router, fake, src := syncAdminApp(t)
	syncBrakeHeld(t, router, fake, src)
	router.sync.DeleteAfter = 24 * time.Hour
	src.users = append(src.users, googleUser("user5"))
	fake.AddUser("gus", ipatest.User{Locked: true})
	fake.AddGroup("google2ipa-managed", ipatest.Group{Members: []string{"user0", "user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8", "user9", "gus"}})
	require.NoError(t, router.syncSetMarker("gus", syncMarker{Kind: syncMarkerSync, At: time.Now().Add(-48 * time.Hour), By: "sync"}))

	body := readBody(t, tc.postForm("/admin/sync/apply", url.Values{"disable": {"5"}, "delete": {"0"}}, htmx))
	router.bg.Wait()
	assert.Contains(t, body, esc(T("sync.admin_plan_changed")))
	assert.Contains(t, body, `name="disable" value="4"`)
	assert.Contains(t, body, `name="delete" value="1"`)
	_, ok := fake.User("gus")
	assert.True(t, ok)
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
		body := readBody(t, tc.postForm(p, url.Values{"disable": {"5"}, "delete": {"0"}}, htmx))
		assert.Contains(t, body, esc(T("sync.admin_busy")), p)
	}
	assert.False(t, locked(fake, "user9"))

	// a run in progress: the pane polls and offers no Apply
	body := readBody(t, tc.get("/admin/sync/status", htmx))
	assert.Contains(t, body, esc(T("sync.admin_running_hint")))
	assert.Contains(t, body, `hx-trigger="load delay:3s"`)
	assert.NotContains(t, body, `hx-post="/admin/sync/apply"`)
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

	// other tabs don't read FreeIPA for the candidates
	before := len(fake.Calls())
	readBody(t, tc.get("/admin/sync?tab=settings"))
	for _, c := range fake.Calls()[before:] {
		assert.NotEqual(t, "user_find", c.Method)
	}
	// with nothing else waiting, a pending import opens Decisions
	assert.Equal(t, "decisions", selectedTab(t, readBody(t, tc.get("/admin/sync"))))

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

// seqSource answers each Users call with the next list, then the last one.
type seqSource struct {
	mu    sync.Mutex
	lists [][]syncSourceUser
}

func (s *seqSource) Users(context.Context) ([]syncSourceUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.lists[0]
	if len(s.lists) > 1 {
		s.lists = s.lists[1:]
	}
	return l, nil
}

// Google shrinks between the Apply check and the background run: the run
// keeps the counts the admin approved and applies nothing.
func TestAdminSyncApplyBackgroundKeepsCap(t *testing.T) {
	tc, router, fake, src := syncAdminApp(t)
	syncBrakeHeld(t, router, fake, src)
	router.syncSrc = &seqSource{lists: [][]syncSourceUser{src.users, src.users[:4]}}

	readBody(t, tc.postForm("/admin/sync/apply", url.Values{"disable": {"5"}, "delete": {"0"}}, htmx))
	router.bg.Wait()
	for i := range 10 {
		assert.False(t, locked(fake, fmt.Sprintf("user%d", i)))
	}
	last, err := router.syncLastRun()
	require.NoError(t, err)
	assert.Equal(t, "skyler", last.By)
	assert.Contains(t, last.Errors, errSyncPlanGrew.Error())
	assert.Empty(t, last.Applied)
	aborted := 0
	for _, ev := range auditEvents(router, "sync run") {
		if ev.Attrs["aborted"] == "true" {
			aborted++
		}
	}
	assert.Equal(t, 1, aborted)
	held, err := router.syncHeld()
	require.NoError(t, err)
	assert.Equal(t, 6, held.HeldDisable)
	assert.Equal(t, "skyler", held.By)
}

func TestAdminSyncStatusReadErrorsShown(t *testing.T) {
	for _, key := range []string{syncRunKey, syncLegacyKey} {
		tc, router, _, _ := syncAdminApp(t)
		router.sync.ImportLegacyLocks = true
		router.storage = &failingGetStorage{Storage: router.storage, prefix: key}
		body := readBody(t, tc.get("/admin/sync/status?tab=settings", htmx))
		assert.Contains(t, body, T("account.fatal_system_error"), key)
	}
}

func TestAdminSyncDecisionCountSameOnEveryTab(t *testing.T) {
	tc, router, fake, _ := syncAdminApp(t)
	router.sync.ImportLegacyLocks = true
	lockedAt := time.Now().Add(-30 * 24 * time.Hour)
	fake.AddUser("gale", ipatest.User{Locked: true, PrincipalExpire: lockedAt})
	fake.AddUser("jane", ipatest.User{Locked: true, PrincipalExpire: lockedAt})
	fake.AddGroup("google2ipa-managed", ipatest.Group{Members: []string{"gale", "jane"}})

	for _, tab := range []string{"decisions", "settings", "last"} {
		body := readBody(t, tc.get("/admin/sync/status?tab="+tab, htmx))
		assert.Contains(t, body, "Decisions · 2<", tab)
	}
}

type panicSource struct{}

func (panicSource) Users(context.Context) ([]syncSourceUser, error) { panic("source blew up") }

// A panic in Apply's check run, before the background hand-off, must not
// leave the run lock claimed and renewed for ever.
func TestAdminSyncApplyPanicReleasesClaim(t *testing.T) {
	tc, router, _, _ := syncAdminApp(t)
	router.syncSrc = panicSource{}

	resp := tc.postForm("/admin/sync/apply", url.Values{"disable": {"0"}, "delete": {"0"}}, htmx)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	release, ok, err := router.lock.claim(syncRunKey, syncRunTTL)
	require.NoError(t, err)
	require.True(t, ok, "run lock still held after the panic")
	release()
}

func TestAdminSyncDecisionGroupWithoutMemberWrite(t *testing.T) {
	tc, router, _, _ := syncAdminApp(t)
	storeSyncResult(t, router, syncLastKey, syncRunResult{At: time.Now(), Plan: syncPlan{NoMemberWrite: []string{"eng"}}, Errors: []string{"x"}})

	body := readBody(t, tc.get("/admin/sync/status?tab=decisions", htmx))
	assert.Contains(t, body, esc(fmt.Sprintf(T("sync.admin_no_member_write"), "eng")))
	assert.Contains(t, body, "Decisions · 1")
}

func TestAdminSyncHeaderAndHeldWithErrors(t *testing.T) {
	tc, router, _, _ := syncAdminApp(t)
	router.sync.Google.OrgUnits = []string{"/Staff"}

	page := readBody(t, tc.get("/admin/sync"))
	assert.Contains(t, page, "Google Workspace · example.org · "+fmt.Sprintf(T("sync.admin_source_ou"), "/Staff")+"<br>")
	assert.Contains(t, page, `<span class="mokey-mono">google2ipa-managed</span> · <span class="text-nowrap">1 synced group</span></p>`)

	storeSyncResult(t, router, syncLastKey, syncRunResult{At: time.Now(), Errors: []string{"boom"}})
	page = readBody(t, tc.get("/admin/sync"))
	assert.Contains(t, page, `mokey-pill is-danger text-nowrap">`+esc(T("sync.admin_failed")))

	// the brake outranks the errors, which stay one click away
	storeSyncResult(t, router, syncHeldKey, syncRunResult{At: time.Now(), Held: true, HeldCount: 1, HeldDisable: 1, Plan: syncPlan{Disable: []string{"rmiller"}}})
	page = readBody(t, tc.get("/admin/sync"))
	assert.Contains(t, page, `mokey-pill is-warn text-nowrap">`+esc(T("sync.admin_held")))
	assert.NotContains(t, page, esc(T("sync.admin_failed")))
	assert.Contains(t, page, `hx-get="/admin/sync/status?tab=last"`)
	assert.Contains(t, page, ">1 error</a></span>")
	assert.Equal(t, "held", selectedTab(t, page))
}

// TestAdminSyncApplyGroupRemovalCap: the held removals are posted with the
// form and a fresh plan with more users losing groups is refused.
func TestAdminSyncApplyGroupRemovalCap(t *testing.T) {
	tc, router, fake, src := syncAdminApp(t)
	allowServiceAccountRemovals(t)
	fake.GrantPrivilege(keytabUser, "Modify Group membership")
	var uids []string
	for i := range 10 {
		uids = append(uids, fmt.Sprintf("user%d", i))
	}
	managed(fake, uids...)
	fake.AddGroup("eng", ipatest.Group{Members: uids})
	src.users = nil
	for _, uid := range uids {
		u := googleUser(uid)
		if uid != "user9" && uid != "user8" {
			u.Groups = []string{"eng@example.org"}
		}
		src.users = append(src.users, u)
	}
	src.users[0].Groups, src.users[1].Groups = nil, nil
	res, _, err := router.syncRunLocked(t.Context(), time.Now(), "", false)
	require.NoError(t, err)
	require.True(t, res.Held)

	body := readBody(t, tc.get("/admin/sync"))
	assert.Contains(t, body, `name="groups" value="4"`)
	assert.Contains(t, body, esc(fmt.Sprintf(T("sync.admin_change_remove"), "eng")))
	assert.Contains(t, body, esc(fmt.Sprintf(T("sync.admin_why_no_match"), T("sync.admin_why_google_group"))))

	src.users[2].Groups = nil
	body = readBody(t, tc.postForm("/admin/sync/apply", url.Values{"disable": {"0"}, "delete": {"0"}, "groups": {"4"}}, htmx))
	router.bg.Wait()
	assert.Contains(t, body, esc(T("sync.admin_plan_changed")))
	assert.Contains(t, body, `name="groups" value="5"`)
	g, _ := fake.Group("eng")
	assert.Len(t, g.Members, 10)

	readBody(t, tc.postForm("/admin/sync/apply", url.Values{"disable": {"0"}, "delete": {"0"}, "groups": {"5"}}, htmx))
	router.bg.Wait()
	g, _ = fake.Group("eng")
	assert.Len(t, g.Members, 5)
}

func rpcCount(fake *ipatest.Server, method string) int {
	n := 0
	for _, c := range fake.Calls() {
		if c.Method == method {
			n++
		}
	}
	return n
}

// syncRulesApp: rule eng targets eng directly, rule ops targets ops-team,
// a member of staff; allow_all is seeded by the fake.
func syncRulesApp(t *testing.T) (*testClient, *Router, *ipatest.Server) {
	t.Helper()
	tc, router, fake, _ := syncAdminApp(t)
	router.sync.Rules = []syncRule{
		{Name: "eng", Conds: map[string][]string{"org_unit": {"/Eng"}}, Groups: []string{"eng"}},
		{Name: "ops", Conds: map[string][]string{"department": {"ops", "sre"}, "title": {"engineer"}}, Groups: []string{"ops-team"}},
	}
	fake.AddGroup("ops-team", ipatest.Group{})
	fake.AddGroup("staff", ipatest.Group{MemberGroups: []string{"ops-team"}})
	fake.AddHBACRule("eng-ssh", ipatest.HBACRule{Groups: []string{"eng"}})
	fake.AddHBACRule("old-db", ipatest.HBACRule{Groups: []string{"eng"}, Disabled: true})
	fake.AddHBACRule("staff-web", ipatest.HBACRule{Groups: []string{"staff"}})
	fake.AddSudoRule("eng-sudo", ipatest.SudoRule{Groups: []string{"eng"}})
	fake.AddSudoRule("finance-sudo", ipatest.SudoRule{Groups: []string{"finance"}})
	return tc, router, fake
}

func TestAdminSyncSettingsRules(t *testing.T) {
	tc, router, fake := syncRulesApp(t)
	storeSyncResult(t, router, syncLastKey, syncRunResult{At: time.Now(), Plan: syncPlan{RuleMatches: map[string]int{"eng": 3}}})

	body := readBody(t, tc.get("/admin/sync/status?tab=settings", htmx))
	assert.Contains(t, body, `<span class="fw-semibold">eng</span>`)
	assert.Contains(t, body, "org_unit: /Eng")
	assert.Contains(t, body, "department: ops, sre · title: engineer")
	assert.Contains(t, body, `<span class="mokey-pill">ops-team</span>`)
	assert.Contains(t, body, fmt.Sprintf(T("sync.admin_rule_matches"), 3))
	// the ops rule is newer than the last run
	assert.Equal(t, 1, strings.Count(body, esc(strings.TrimSuffix(T("sync.admin_rule_matches"), "%d"))))

	assert.Contains(t, body, `<span class="mokey-pill is-ok">eng-ssh</span>`)
	assert.Contains(t, body, `<span class="mokey-pill is-ok">eng-sudo</span>`)
	assert.Contains(t, body, `<span class="mokey-pill is-ok">staff-web · `+esc(fmt.Sprintf(T("sync.admin_rule_via"), "staff"))+`</span>`)
	assert.Contains(t, body, `<span class="mokey-pill is-ok">allow_all · `+esc(T("sync.admin_rule_all_users"))+`</span>`)
	assert.Contains(t, body, `<span class="mokey-pill is-muted">old-db · `+esc(T("sync.admin_rule_disabled"))+`</span>`)
	assert.NotContains(t, body, "finance-sudo")
	assert.NotContains(t, body, esc(T("sync.admin_rules_failed")))
	assert.Contains(t, body, T("sync.admin_set_brake"))

	assert.Equal(t, 1, rpcCount(fake, "hbacrule_find"))
	assert.Equal(t, 1, rpcCount(fake, "sudorule_find"))
	assert.Equal(t, 2, rpcCount(fake, "group_show"))
	for _, c := range fake.Calls() {
		if c.Method == "group_show" || strings.HasSuffix(c.Method, "rule_find") {
			assert.Equal(t, true, c.Options["all"], c.Method)
		}
	}
	assert.Empty(t, writeCalls(fake))

	// other tabs don't read the rules
	readBody(t, tc.get("/admin/sync/status?tab=last", htmx))
	assert.Equal(t, 1, rpcCount(fake, "hbacrule_find"))
}

func TestAdminSyncSettingsNoRulesNoLookups(t *testing.T) {
	tc, _, fake, _ := syncAdminApp(t)
	body := readBody(t, tc.get("/admin/sync/status?tab=settings", htmx))
	assert.Contains(t, body, T("sync.admin_set_brake"))
	assert.NotContains(t, body, T("sync.admin_rules_title"))
	for _, m := range []string{"hbacrule_find", "sudorule_find", "group_show"} {
		assert.Zero(t, rpcCount(fake, m), m)
	}
}

func TestAdminSyncSettingsRulesLookupFails(t *testing.T) {
	tc, _, fake := syncRulesApp(t)
	fake.Handle("sudorule_find", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: 4301, Message: "boom"}
	})

	body := readBody(t, tc.get("/admin/sync/status?tab=settings", htmx))
	assert.Contains(t, body, esc(T("sync.admin_rules_failed")))
	assert.Contains(t, body, `<span class="fw-semibold">eng</span>`)
	assert.Contains(t, body, T("sync.admin_set_brake"))
	assert.NotContains(t, body, "eng-ssh")
	assert.Empty(t, writeCalls(fake))
}

// TestAdminSyncSettingsRuleGroupMissing: a rule group missing in FreeIPA is
// marked, and the other targets keep their HBAC and sudo rules.
func TestAdminSyncSettingsRuleGroupMissing(t *testing.T) {
	tc, router, fake := syncRulesApp(t)
	router.sync.Rules[1].Groups = []string{"ghost-team"}

	body := readBody(t, tc.get("/admin/sync/status?tab=settings", htmx))
	assert.NotContains(t, body, esc(T("sync.admin_rules_failed")))
	assert.Contains(t, body, `<span class="mokey-pill">ghost-team</span>`)
	assert.Contains(t, body, esc(T("sync.admin_rule_group_missing")))
	assert.Contains(t, body, `<span class="mokey-pill is-ok">eng-ssh</span>`)
	assert.Empty(t, writeCalls(fake))
}

func TestAdminSyncSettingsRuleGroupLookupFails(t *testing.T) {
	tc, _, fake := syncRulesApp(t)
	fake.Handle("group_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: 4301, Message: "boom"}
	})

	body := readBody(t, tc.get("/admin/sync/status?tab=settings", htmx))
	assert.Contains(t, body, esc(T("sync.admin_rules_failed")))
	assert.NotContains(t, body, "eng-ssh")
	assert.NotContains(t, body, esc(T("sync.admin_rule_group_missing")))
}

// TestSyncHeldTableCountsHiddenRows: "more" counts hidden (user, group)
// rows, also for a stored plan that kept only the first users.
func TestSyncHeldTableCountsHiddenRows(t *testing.T) {
	full := syncPlan{RemoveGroups: map[string][]string{}, GroupWhy: map[string]map[string][]string{}}
	for i := range 30 {
		full.RemoveGroups[fmt.Sprintf("user%02d", i)] = []string{"eng", "ops"}
	}
	more := func(n int) string { return fmt.Sprintf(T("admin.lifecycle_more"), n) }

	tb := syncHeldTable("en", full, 0, 0, false)
	require.Len(t, tb.Rows, syncSampleN)
	assert.Equal(t, more(60-syncSampleN), tb.More)

	held := syncHeldOf(time.Now(), full, nil)
	tb = syncHeldTable("en", held.Plan, held.HeldDisable+held.HeldDelete+held.HeldGroupRemovals, 0, false)
	assert.Equal(t, more(60-syncSampleN), tb.More)
}

func TestSyncHeldTableDryRunAdds(t *testing.T) {
	p := syncPlan{
		AddGroups: map[string][]string{"jesse": {"eng", "eng-sudo"}},
		GroupWhy:  map[string]map[string][]string{"jesse": {"eng": {syncWhyGoogle}, "eng-sudo": {"everyone", "eng-ou"}}},
	}
	assert.Nil(t, syncHeldTable("en", p, 0, 0, false))
	tb := syncHeldTable("en", p, 0, 0, true)
	assert.Equal(t, []syncRow{
		{"jesse", fmt.Sprintf(T("sync.admin_change_add"), "eng"), fmt.Sprintf(T("sync.admin_why_wanted"), T("sync.admin_why_google_group"))},
		{"jesse", fmt.Sprintf(T("sync.admin_change_add"), "eng-sudo"), fmt.Sprintf(T("sync.admin_why_wanted"), "everyone, eng-ou")},
	}, tb.Rows)
}

// TestAdminSyncDryRunListsAdds: a rule that matches everyone shows up in
// the dry run by name, not only as a count.
func TestAdminSyncDryRunListsAdds(t *testing.T) {
	tc, router, fake, src := syncAdminApp(t)
	fake.GrantPrivilege(keytabUser, "Modify Group membership")
	fake.AddGroup("eng-sudo", ipatest.Group{})
	router.sync.Rules = []syncRule{{Name: "everyone", Conds: map[string][]string{"org_unit": {"/"}}, Groups: []string{"eng-sudo"}}}
	managed(fake, "jesse")
	u := googleUser("jesse")
	u.Attrs = map[string]string{"org_unit": "/"}
	src.users = []syncSourceUser{u}

	body := readBody(t, tc.postForm("/admin/sync/dry-run", nil, htmx))
	assert.Contains(t, body, esc(fmt.Sprintf(T("sync.admin_change_add"), "eng-sudo")))
	assert.Contains(t, body, esc(fmt.Sprintf(T("sync.admin_why_wanted"), "everyone")))

	// adds are never held: the Held tab doesn't list them
	syncBrakeHeld(t, router, fake, src)
	body = readBody(t, tc.get("/admin/sync/status?tab=held", htmx))
	assert.NotContains(t, body, esc(fmt.Sprintf(T("sync.admin_change_add"), "eng-sudo")))
}
