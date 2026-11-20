package server

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func newAppsTestApp(t *testing.T, configure func()) (*fiber.App, *Router, *fakeHydra) {
	t.Helper()
	hy := newFakeHydra()
	t.Cleanup(hy.Close)

	app, router, fake := newTestAppWith(t, func() {
		viper.Set("hydra.admin_url", hy.srv.URL)
		viper.Set("accounts.enable_apps", true)
		viper.Set("hydra.clients", []map[string]interface{}{
			{"client_id": "grafana", "groups": []string{"grafana-users"}},
			{"client_id": "vault", "groups": []string{"hr", "vault-users"}},
			{"client_id": "payroll", "groups": []string{"hr"}},
			{"client_id": "lab", "groups": []string{"chemists"}},
		})
		if configure != nil {
			configure()
		}
	})

	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"chemists"}})
	fake.AddUser("skyler", ipatest.User{Password: "Secret123!"})
	fake.AddGroup("grafana-users", ipatest.Group{ManagerUsers: []string{"skyler"}})
	fake.AddGroup("vault-users", ipatest.Group{ManagerUsers: []string{"skyler"}})
	fake.AddGroup("hr", ipatest.Group{}) // no sponsor: not requestable

	hy.seedClient(map[string]interface{}{
		"client_id": "wiki", "client_name": "Team Wiki", "client_uri": "https://wiki.example.com",
		"client_secret": "wiki-s3cret", "redirect_uris": []string{"https://wiki.example.com/oauth/cb"},
	})
	hy.seedClient(map[string]interface{}{"client_id": "grafana", "client_name": "Grafana", "client_uri": "https://grafana.example.com"})
	hy.seedClient(map[string]interface{}{"client_id": "vault", "client_name": "Vault"})
	hy.seedClient(map[string]interface{}{"client_id": "payroll", "client_name": "Payroll"})
	hy.seedClient(map[string]interface{}{"client_id": "lab", "client_name": "Lab Notes", "grant_types": []string{"authorization_code", "refresh_token"}})
	hy.seedClient(map[string]interface{}{"client_id": "batch", "client_name": "Batch Job", "grant_types": []string{"client_credentials"}})
	// several pages, so the Link-header paging is exercised
	hy.clientsPage = 2

	return app, router, hy
}

const requestButton = `hx-vals='{"client": "`

func TestAppsCatalogStates(t *testing.T) {
	assert := assert.New(t)
	app, router, _ := newAppsTestApp(t, nil)
	router.addGroupRequest("vault-users", "walter", groupRequestJoin, "")

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.get("/apps")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)
	assert.Contains(body, "apps-tab")

	// available: no restriction (wiki) or member of an allowed group (lab)
	assert.Contains(body, `href="https://wiki.example.com"`)
	assert.Contains(body, "Lab Notes")
	// requestable through the sponsored group, not linked yet
	assert.Contains(body, requestButton+`grafana"}'`)
	assert.NotContains(body, "grafana.example.com")
	// pending: the join request in the sponsor queue wins over hr
	assert.Contains(body, "Vault")
	assert.Contains(body, T("apps.pending"))
	assert.NotContains(body, requestButton+`vault"}'`)
	// no way in, or not a user-facing client
	assert.NotContains(body, "Payroll")
	assert.NotContains(body, "Batch Job")
	// nothing beyond name and client_uri leaks
	assert.NotContains(body, "wiki-s3cret")
	assert.NotContains(body, "/oauth/cb")
}

func TestAppsRequestAccess(t *testing.T) {
	assert := assert.New(t)
	app, router, _ := newAppsTestApp(t, nil)

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	tc.get("/apps")

	resp := tc.postForm("/apps/request", url.Values{"client": {"grafana"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	reqs := router.loadGroupRequests("grafana-users")
	if assert.Len(reqs, 1) {
		assert.Equal("walter", reqs[0].Username)
		assert.Equal(groupRequestJoin, reqs[0].Type)
	}
	body := readBody(t, resp)
	assert.Contains(body, `id="apps-pane"`)
	assert.NotContains(body, requestButton+`grafana"}'`)

	// the sponsor sees it in the usual queue
	sponsor := newTestClient(t, app)
	sponsor.login("skyler", "Secret123!")
	assert.Contains(readBody(t, sponsor.get("/groups")), "walter")

	// available, unrequestable and unknown clients are refused
	for _, client := range []string{"wiki", "payroll", "batch", "nope"} {
		resp = tc.postForm("/apps/request", url.Values{"client": {client}}, htmx)
		assert.Equal(fiber.StatusBadRequest, resp.StatusCode, client)
	}
	assert.Empty(router.loadGroupRequests("hr"))
}

func TestAppsGroupsDisabled(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newAppsTestApp(t, func() { viper.Set("accounts.enable_groups", false) })

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	body := readBody(t, tc.get("/apps"))
	assert.Contains(body, "Team Wiki")
	assert.NotContains(body, "Grafana")
	assert.NotContains(body, "Vault")

	resp := tc.postForm("/apps/request", url.Values{"client": {"grafana"}}, htmx)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)
}

func TestAppsDisabled(t *testing.T) {
	for name, configure := range map[string]func(){
		"flag off": func() { viper.Set("accounts.enable_apps", false) },
		"no hydra": func() { viper.Set("hydra.admin_url", nil) },
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			app, _, _ := newAppsTestApp(t, configure)

			tc := newTestClient(t, app)
			tc.login("walter", "Secret123!")

			assert.Equal(fiber.StatusNotFound, tc.get("/apps").StatusCode)
			assert.NotContains(readBody(t, tc.get("/account")), "apps-tab")
			resp := tc.postForm("/apps/request", url.Values{"client": {"grafana"}}, htmx)
			assert.Equal(fiber.StatusNotFound, resp.StatusCode)
		})
	}
}

func TestAppsMappedGroupNotRequestable(t *testing.T) {
	app, router, _ := newAppsTestApp(t, nil)
	router.sync = &syncConfig{ManagedGroup: "google2ipa-managed", GroupMapping: map[string][]string{"ops@example.org": {"grafana-users"}}}

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	body := readBody(t, tc.get("/apps"))
	assert.False(t, strings.Contains(body, requestButton+`grafana"}'`), "Google owns the membership")
	assert.True(t, strings.Contains(body, requestButton+`vault"}'`), "other groups stay requestable")
}

func TestAppsCatalogMetadata(t *testing.T) {
	assert := assert.New(t)
	app, _, hy := newAppsTestApp(t, nil)
	meta := func(m map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"mokey": m}
	}
	hy.seedClient(map[string]interface{}{"client_id": "notes", "client_name": "Chem Notes", "metadata": meta(map[string]interface{}{"access": "groups", "groups": []string{"Chemists"}})})
	hy.seedClient(map[string]interface{}{"client_id": "dash", "client_name": "Dashboards", "metadata": meta(map[string]interface{}{"access": "groups", "groups": []string{"grafana-users"}})})
	hy.seedClient(map[string]interface{}{"client_id": "people", "client_name": "People Admin", "metadata": meta(map[string]interface{}{"access": "groups", "groups": []string{"hr"}})})
	hy.seedClient(map[string]interface{}{"client_id": "hidden", "client_name": "Hidden Tool", "metadata": meta(map[string]interface{}{"access": "all", "catalog": false})})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	body := readBody(t, tc.get("/apps"))

	assert.Contains(body, "Chem Notes")
	assert.Contains(body, requestButton+`dash"}'`)
	assert.NotContains(body, "People Admin")
	assert.NotContains(body, "Hidden Tool")
}

func TestAppsInvalidMetadataLogsOnce(t *testing.T) {
	app, _, hy := newAppsTestApp(t, nil)
	hy.seedClient(map[string]interface{}{"client_id": "broken", "client_name": "Broken", "metadata": map[string]interface{}{"mokey": map[string]interface{}{"access": "everyone"}}})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	logs := captureSlog(t)
	body := readBody(t, tc.get("/apps"))

	assert.NotContains(t, body, "Broken")
	assert.Equal(t, 1, strings.Count(logs.String(), "Invalid mokey metadata"))
}
