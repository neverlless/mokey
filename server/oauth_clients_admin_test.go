package server

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAppsAdminApp signs in gus, an admin, with manage_clients on unless
// configure turns it off.
func newAppsAdminApp(t *testing.T, configure func()) (*testClient, *Router, *fakeHydra) {
	t.Helper()
	hy := newFakeHydra()
	t.Cleanup(hy.Close)
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("hydra.admin_url", hy.srv.URL)
		viper.Set("hydra.manage_clients", true)
		viper.Set("hydra.public_url", "https://auth.example.org")
		viper.Set("admin.enabled", true)
		viper.Set("admin.users", []string{"gus"})
		viper.Set("hydra.clients", []map[string]interface{}{
			{"client_id": "wiki", "groups": []string{"staff"}},
			{"client_id": "ghost", "groups": []string{"staff"}},
		})
		if configure != nil {
			configure()
		}
	})
	fake.AddUser("gus", ipatest.User{Password: "Secret123!"})
	fake.AddUser("skyler", ipatest.User{Password: "Secret123!"})
	fake.AddGroup("devs", ipatest.Group{})
	fake.AddGroup("ops", ipatest.Group{})
	fake.AddGroup("staff", ipatest.Group{})

	hy.seedClient(map[string]interface{}{
		"client_id": "grafana", "client_name": "Grafana", "client_uri": "https://grafana.example.org",
		"redirect_uris": []string{"https://grafana.example.org/login/generic_oauth"},
		"scope":         "openid profile email", "metadata": map[string]interface{}{"mokey": map[string]interface{}{"access": "all"}},
		"allowed_cors_origins": []string{"https://grafana.example.org"}, "skip_consent": true,
	})
	hy.seedClient(map[string]interface{}{
		"client_id": "gitea", "client_name": "Gitea", "scope": "openid ssh",
		"redirect_uris": []string{"https://git.example.org/cb"},
		"metadata":      map[string]interface{}{"mokey": map[string]interface{}{"access": "groups", "groups": []string{"devs", "ops"}}},
	})
	hy.seedClient(map[string]interface{}{"client_id": "wiki", "client_name": "Wiki", "redirect_uris": []string{"https://wiki.example.org/cb"}})
	hy.seedClient(map[string]interface{}{"client_id": "backup-agent", "client_name": "Backup agent", "grant_types": []string{"client_credentials"}})

	appsFake = fake
	tc := newTestClient(t, app)
	tc.login("gus", "Secret123!")
	tc.getCSRF("/admin/apps")
	return tc, router, hy
}

// appsFake is the FreeIPA fake of the last newAppsAdminApp.
var appsFake *ipatest.Server

func formOf(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

func TestAdminAppsOff(t *testing.T) {
	for name, off := range map[string]func(){
		"manage_clients": func() { viper.Set("hydra.manage_clients", false) },
		"admin":          func() { viper.Set("admin.enabled", false) },
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			hy := newFakeHydra()
			t.Cleanup(hy.Close)
			app, _, fake := newTestAppWith(t, func() {
				viper.Set("hydra.admin_url", hy.srv.URL)
				viper.Set("admin.enabled", true)
				viper.Set("admin.users", []string{"gus"})
				viper.Set("hydra.manage_clients", true)
				off()
			})
			fake.AddUser("gus", ipatest.User{Password: "Secret123!"})
			tc := newTestClient(t, app)
			tc.login("gus", "Secret123!")
			body := readBody(t, tc.get("/admin/people"))
			assert.NotContains(body, `href="/admin/apps"`)
			for _, p := range []string{"/admin/apps", "/admin/apps/new", "/admin/apps/x"} {
				assert.Equal(fiber.StatusNotFound, tc.get(p).StatusCode, p)
			}
		})
	}
}

func TestAdminAppsNonAdmin(t *testing.T) {
	admin, _, hy := newAppsAdminApp(t, nil)
	tc := newTestClient(t, admin.app)
	tc.login("skyler", "Secret123!")
	tc.getCSRF("/account")
	assert.Equal(t, fiber.StatusForbidden, tc.get("/admin/apps").StatusCode)
	assert.Equal(t, fiber.StatusForbidden, tc.get("/admin/apps/gitea").StatusCode)
	resp := tc.postForm("/admin/apps/gitea/delete", nil, htmx)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Zero(t, hy.clientWrites)
	assert.NotContains(t, readBody(t, tc.get("/account")), `href="/admin/apps"`)
}

func TestAdminAppsList(t *testing.T) {
	assert := assert.New(t)
	tc, _, _ := newAppsAdminApp(t, nil)
	body := readBody(t, tc.get("/admin/apps"))
	assert.Contains(body, `href="/admin/apps"`)
	assert.Contains(body, `aria-current="page"><i class="fa fa-plug"`)
	for _, s := range []string{"Grafana", "Gitea", "Wiki", "Backup agent", "ghost",
		T("admin_apps.kind_web"), T("admin_apps.kind_machine"), T("admin_apps.everyone"),
		T("admin_apps.machine_read_only"), T("admin_apps.in_config"), T("admin_apps.missing"), ">devs<", ">staff<"} {
		assert.Contains(body, s)
	}
	assert.Contains(body, `href="/admin/apps/gitea"`)
	assert.NotContains(body, `href="/admin/apps/backup-agent"`)
	assert.NotContains(body, `href="/admin/apps/ghost"`)
	// config entries without a Hydra client come last
	assert.Less(strings.Index(body, "Backup agent"), strings.Index(body, ">ghost<"))
}

// spyStorage records every value written through the router's storage.
type spyStorage struct {
	fiber.Storage
	mu     sync.Mutex
	writes []string
}

func (s *spyStorage) Set(key string, val []byte, exp time.Duration) error {
	s.mu.Lock()
	s.writes = append(s.writes, key+"="+string(val))
	s.mu.Unlock()
	return s.Storage.Set(key, val, exp)
}

func spyOn(router *Router) *spyStorage {
	spy := &spyStorage{Storage: router.storage}
	router.storage = spy
	router.lock.storage = spy
	return spy
}

// assertSecretGone checks that secret shows up in no later page and was
// never written to storage or the audit log.
func assertSecretGone(t *testing.T, tc *testClient, router *Router, spy *spyStorage, secret string, pages ...string) {
	t.Helper()
	for _, p := range pages {
		assert.NotContains(t, readBody(t, tc.get(p)), secret, p)
	}
	for _, w := range spy.writes {
		assert.NotContains(t, w, secret)
	}
	for _, e := range auditRecent(router.storage, auditRingSize) {
		for _, v := range e.Attrs {
			assert.NotContains(t, v, secret)
		}
	}
}

// Review Focus 4
func TestAdminAppsCreateShowsSecretOnce(t *testing.T) {
	assert := assert.New(t)
	tc, router, hy := newAppsAdminApp(t, nil)
	spy := spyOn(router)

	resp := tc.postForm("/admin/apps", formOf("name", "Outline", "id", "outline", "uri", "https://docs.example.org",
		"kind", "web", "redirect_uris", "https://docs.example.org/auth/oidc.callback", "scopes", "profile",
		"access", "groups", "groups", "devs", "groups_add", "ops", "catalog", "1"), htmx)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal("no-store", resp.Header.Get("Cache-Control"))
	assert.Empty(resp.Header.Get("HX-Redirect"))
	assert.Empty(resp.Header.Get("HX-Push-Url"))
	body := readBody(t, resp)
	stored := hy.storedClient("outline")
	require.NotNil(t, stored, body)
	secret, _ := stored["client_secret"].(string)
	require.NotEmpty(t, secret)
	assert.Equal(map[string]interface{}{"access": "groups", "groups": []interface{}{"devs", "ops"}, "catalog": true}, stored["metadata"].(map[string]interface{})["mokey"])

	assert.Contains(body, fmt.Sprintf(T("admin_apps.secret_ready"), "Outline"))
	assert.Contains(body, `data-copy="`+secret+`"`)
	assert.Contains(body, "https://auth.example.org/.well-known/openid-configuration")
	assert.Contains(body, "https://auth.example.org/oauth2/token")
	assert.Contains(body, `href="/admin/apps/outline"`)
	assert.NotContains(body, "hx-push-url")

	assertSecretGone(t, tc, router, spy, secret, "/admin/apps", "/admin/apps/outline")
}

func TestAdminAppsRotateShowsSecret(t *testing.T) {
	assert := assert.New(t)
	tc, router, hy := newAppsAdminApp(t, nil)
	spy := spyOn(router)
	resp := tc.postForm("/admin/apps/gitea/rotate", nil, htmx)
	assert.Equal("#admin", resp.Header.Get("HX-Retarget"))
	assert.Equal("innerHTML", resp.Header.Get("HX-Reswap"))
	assert.Equal("no-store", resp.Header.Get("Cache-Control"))
	assert.Empty(resp.Header.Get("HX-Push-Url"))
	body := readBody(t, resp)
	secret, _ := hy.storedClient("gitea")["client_secret"].(string)
	require.NotEmpty(t, secret)
	assert.Contains(body, fmt.Sprintf(T("admin_apps.secret_new"), "Gitea"))
	assert.Contains(body, `data-copy="`+secret+`"`)
	assertSecretGone(t, tc, router, spy, secret, "/admin/apps", "/admin/apps/gitea")
}

func TestAdminAppsPublicClient(t *testing.T) {
	assert := assert.New(t)
	tc, _, hy := newAppsAdminApp(t, func() { viper.Set("hydra.public_url", "") })
	resp := tc.postForm("/admin/apps", formOf("name", "Lab CLI", "id", "labcli", "kind", "public",
		"redirect_uris", "http://127.0.0.1/callback", "scopes", "offline_access", "access", "all"), htmx)
	body := readBody(t, resp)
	assert.Equal("none", hy.storedClient("labcli")["token_endpoint_auth_method"], body)
	assert.Contains(body, fmt.Sprintf(T("admin_apps.secret_ready"), "Lab CLI"))
	assert.Contains(body, `data-copy="labcli"`)
	assert.NotContains(body, T("admin_apps.client_secret"))
	assert.Contains(body, T("admin_apps.public_url_hint"))
}

func TestAdminAppsSlashID(t *testing.T) {
	assert := assert.New(t)
	tc, _, hy := newAppsAdminApp(t, nil)
	hy.seedClient(map[string]interface{}{"client_id": "team/notes", "client_name": "Notes",
		"redirect_uris": []string{"https://notes.example.org/cb"}})
	assert.Contains(readBody(t, tc.get("/admin/apps")), `href="/admin/apps/team%2Fnotes"`)
	resp := tc.get("/admin/apps/team%2Fnotes")
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)
	assert.Contains(body, `value="Notes"`)
	assert.Contains(body, `hx-post="/admin/apps/team%2Fnotes"`)
	resp = tc.postForm("/admin/apps/team%2Fnotes", formOf("name", "Team notes", "redirect_uris", "https://notes.example.org/cb", "access", "all"), htmx)
	assert.Equal("/admin/apps", resp.Header.Get("HX-Redirect"), readBody(t, resp))
	assert.Equal("Team notes", hy.storedClient("team/notes")["client_name"])
}

func TestAdminAppsGroupLookup(t *testing.T) {
	assert := assert.New(t)
	tc, _, _ := newAppsAdminApp(t, nil)
	before := len(appsFake.Calls())
	body := readBody(t, tc.get("/admin/apps/new"))
	assert.Contains(body, `<option value="devs">`)
	var finds []ipatest.Call
	for _, c := range appsFake.Calls()[before:] {
		if c.Method == "group_find" {
			finds = append(finds, c)
		}
	}
	require.Len(t, finds, 1)
	assert.Equal(true, finds[0].Options["pkey_only"])
	assert.NotContains(finds[0].Options, "all")
}

func TestAdminAppsCreateErrors(t *testing.T) {
	assert := assert.New(t)
	tc, _, hy := newAppsAdminApp(t, nil)
	body := readBody(t, tc.postForm("/admin/apps", formOf("name", "X", "id", "grafana", "kind", "web",
		"redirect_uris", "https://x.example.org/cb", "access", "all"), htmx))
	assert.Contains(body, T("admin_apps.err_id_taken"))
	body = readBody(t, tc.postForm("/admin/apps", formOf("name", "X", "kind", "web", "redirect_uris", "javascript:alert(1)",
		"access", "groups", "groups_add", "nope"), htmx))
	assert.Contains(body, T("admin_apps.err_redirect_uri"))
	assert.Contains(body, `value="X"`)
	assert.Equal(1, hy.clientWrites) // only the 409 attempt
}

// Review Focus 3
func TestAdminAppsEditKeepsUnknownFields(t *testing.T) {
	assert := assert.New(t)
	tc, _, hy := newAppsAdminApp(t, nil)
	body := readBody(t, tc.get("/admin/apps/grafana"))
	assert.Contains(body, `value="Grafana"`)
	assert.Contains(body, T("admin_apps.rotate"))
	assert.Contains(body, fmt.Sprintf(T("admin_apps.delete_confirm"), "Grafana"))

	resp := tc.postForm("/admin/apps/grafana", formOf("name", "Grafana Prod", "uri", "https://grafana.example.org",
		"redirect_uris", "https://grafana.example.org/login/generic_oauth", "scopes", "profile", "scopes", "email",
		"access", "all", "catalog", "1"), htmx)
	require.Equal(t, "/admin/apps", resp.Header.Get("HX-Redirect"), readBody(t, resp))
	cl := hy.storedClient("grafana")
	assert.Equal("Grafana Prod", cl["client_name"])
	assert.Equal(true, cl["skip_consent"])
	assert.Equal([]interface{}{"https://grafana.example.org"}, cl["allowed_cors_origins"])
	assert.Equal("openid profile email", cl["scope"])
}

// Review Focus 2
func TestAdminAppsConfigClientAccessReadOnly(t *testing.T) {
	assert := assert.New(t)
	tc, _, hy := newAppsAdminApp(t, nil)
	body := readBody(t, tc.get("/admin/apps/wiki"))
	assert.Contains(body, T("admin_apps.config_access"))
	assert.NotContains(body, `name="access"`)

	resp := tc.postForm("/admin/apps/wiki", formOf("name", "Wiki", "redirect_uris", "https://wiki.example.org/cb",
		"access", "all", "groups", "devs"), htmx)
	require.Equal(t, "/admin/apps", resp.Header.Get("HX-Redirect"), readBody(t, resp))
	mk := hy.storedClient("wiki")["metadata"].(map[string]interface{})["mokey"].(map[string]interface{})
	assert.NotContains(mk, "access")
	assert.NotContains(mk, "groups")
	assert.Equal(false, mk["catalog"])
}

// Review Focus 1
func TestAdminAppsNarrowingConfirmsAndRevokes(t *testing.T) {
	assert := assert.New(t)
	tc, router, hy := newAppsAdminApp(t, nil)
	hy.seedConsentSession("skyler", fakeConsentSession{ClientID: "grafana"})
	form := formOf("name", "Grafana", "redirect_uris", "https://grafana.example.org/login/generic_oauth",
		"access", "groups", "groups", "devs")

	resp := tc.postForm("/admin/apps/grafana", form, htmx)
	body := readBody(t, resp)
	assert.Empty(resp.Header.Get("HX-Redirect"))
	assert.Contains(body, fmt.Sprintf(T("admin_apps.narrow_warn"), "Grafana"))
	assert.Contains(body, T("admin_apps.narrow_confirm"))
	assert.Contains(body, `name="confirm" value="1"`)
	assert.Zero(hy.clientWrites)

	form.Set("confirm", "1")
	resp = tc.postForm("/admin/apps/grafana", form, htmx)
	require.Equal(t, "/admin/apps", resp.Header.Get("HX-Redirect"), readBody(t, resp))
	router.bg.Wait()
	assert.NotContains(consentClients(hy, "skyler"), "grafana")

	// widening needs no confirm
	form = formOf("name", "Gitea", "redirect_uris", "https://git.example.org/cb", "access", "all")
	resp = tc.postForm("/admin/apps/gitea", form, htmx)
	assert.Equal("/admin/apps", resp.Header.Get("HX-Redirect"))
}

func TestAdminAppsDelete(t *testing.T) {
	tc, router, hy := newAppsAdminApp(t, nil)
	hy.seedConsentSession("skyler", fakeConsentSession{ClientID: "gitea"})
	resp := tc.postForm("/admin/apps/gitea/delete", nil, htmx)
	assert.Equal(t, "/admin/apps", resp.Header.Get("HX-Redirect"))
	assert.Nil(t, hy.storedClient("gitea"))
	assert.NotContains(t, consentClients(hy, "skyler"), "gitea")
	assert.Len(t, auditEvents(router, "oauth client deleted"), 1)

	resp = tc.postForm("/admin/apps/backup-agent/delete", nil, htmx)
	assert.Contains(t, readBody(t, resp), T("admin_apps.err_read_only"))
	assert.Equal(t, fiber.StatusNotFound, tc.get("/admin/apps/backup-agent").StatusCode)
	assert.Equal(t, fiber.StatusNotFound, tc.get("/admin/apps/missing").StatusCode)
}

// Review Focus 5
func TestAdminAppsHydraDown(t *testing.T) {
	assert := assert.New(t)
	tc, _, hy := newAppsAdminApp(t, nil)
	hy.Close()
	resp := tc.get("/admin/apps")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), T("admin_apps.err_hydra"))
	resp = tc.get("/admin/apps/gitea")
	assert.Contains(readBody(t, resp), T("admin_apps.err_hydra"))
	body := readBody(t, tc.postForm("/admin/apps", formOf("name", "X", "kind", "web",
		"redirect_uris", "https://x.example.org/cb", "access", "all"), htmx))
	assert.Contains(body, T("admin_apps.err_hydra"))
	body = readBody(t, tc.postForm("/admin/apps/gitea", formOf("name", "Gitea", "access", "all"), htmx))
	assert.Contains(body, T("admin_apps.err_hydra"))
	assert.NotContains(body, `name="name"`)
	body = readBody(t, tc.postForm("/admin/apps/gitea/rotate", nil, htmx))
	assert.Contains(body, T("admin_apps.err_hydra"))
}

func TestAdminAppsNarrowingSweepSkipsWhenRunning(t *testing.T) {
	tc, router, hy := newAppsAdminApp(t, nil)
	hy.seedConsentSession("skyler", fakeConsentSession{ClientID: "grafana"})
	release, ok, err := router.lock.claim(appNarrowSweepKey, time.Minute)
	require.True(t, ok, err)
	defer release()
	resp := tc.postForm("/admin/apps/grafana", formOf("name", "Grafana", "redirect_uris", "https://grafana.example.org/login/generic_oauth",
		"access", "groups", "groups", "devs", "confirm", "1"), htmx)
	require.Equal(t, "/admin/apps", resp.Header.Get("HX-Redirect"))
	router.bg.Wait()
	assert.Contains(t, consentClients(hy, "skyler"), "grafana")
}
