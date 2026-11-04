package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newConsentRevokeApp: Hydra on, lubelogger limited to chemists, wiki open.
// walter holds consent for both; skyler sponsors chemists.
func newConsentRevokeApp(t *testing.T) (*fiber.App, *Router, *ipatest.Server, *fakeHydra) {
	t.Helper()
	hy := newFakeHydra()
	t.Cleanup(hy.Close)

	app, router, fake := newTestAppWith(t, func() {
		viper.Set("hydra.admin_url", hy.srv.URL)
	})
	viper.SetConfigType("toml")
	require.NoError(t, viper.MergeConfig(strings.NewReader(`
[[hydra.clients]]
client_id = "lubelogger"
groups = ["chemists"]
`)))

	fake.AddUser("skyler", ipatest.User{Password: "Secret123!"})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	fake.AddGroup("chemists", ipatest.Group{ManagerUsers: []string{"skyler"}, Members: []string{"walter"}})
	hy.seedConsentSession("walter", fakeConsentSession{ClientID: "lubelogger"})
	hy.seedConsentSession("walter", fakeConsentSession{ClientID: "wiki"})
	return app, router, fake, hy
}

func consentClients(hy *fakeHydra, subject string) []string {
	ids := []string{}
	for _, s := range hy.consentSessions[subject] {
		ids = append(ids, s.ClientID)
	}
	return ids
}

func TestLeaveApproveRevokesConsent(t *testing.T) {
	assert := assert.New(t)
	app, router, _, hy := newConsentRevokeApp(t)
	router.addGroupRequest("chemists", "walter", groupRequestLeave)

	tc := newTestClient(t, app)
	tc.login("skyler", "Secret123!")
	resp := tc.postForm("/groups/approve", url.Values{"group": {"chemists"}, "username": {"walter"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	router.bg.Wait()

	assert.Equal([]revokedConsent{{Subject: "walter", Client: "lubelogger"}}, hy.revokedConsents)
	assert.Equal([]string{"wiki"}, consentClients(hy, "walter"))
}

func TestSponsorRemoveRevokesConsent(t *testing.T) {
	assert := assert.New(t)
	app, router, _, hy := newConsentRevokeApp(t)

	tc := newTestClient(t, app)
	tc.login("skyler", "Secret123!")
	resp := tc.postForm("/groups/remove-member", url.Values{"group": {"chemists"}, "username": {"walter"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	router.bg.Wait()

	assert.Equal([]revokedConsent{{Subject: "walter", Client: "lubelogger"}}, hy.revokedConsents)
	assert.Equal([]string{"wiki"}, consentClients(hy, "walter"))
}

func TestConsentDenialRevokesConsent(t *testing.T) {
	assert := assert.New(t)
	app, _, fake, hy := newConsentRevokeApp(t)
	// removed from chemists directly in FreeIPA, then tries lubelogger again
	fake.AddUser("jesse", ipatest.User{Password: "Secret123!"})
	hy.seedConsentSession("jesse", fakeConsentSession{ClientID: "lubelogger"})
	hy.seedConsentSession("jesse", fakeConsentSession{ClientID: "wiki"})
	hy.seedConsentForClient("consent-j", "jesse", "lubelogger")

	resp := newTestClient(t, app).get("/oauth/consent?consent_challenge=consent-j")
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
	assert.Equal([]revokedConsent{{Subject: "jesse", Client: "lubelogger"}}, hy.revokedConsents)
	assert.Equal([]string{"wiki"}, consentClients(hy, "jesse"))
}

func TestConsentSweep(t *testing.T) {
	assert := assert.New(t)
	_, router, fake, hy := newConsentRevokeApp(t)
	// removed from chemists directly in FreeIPA
	fake.AddGroup("chemists", ipatest.Group{ManagerUsers: []string{"skyler"}, Members: []string{}, MemberGroups: []string{"dea"}})
	// hank is in chemists only through the nested dea group
	fake.AddUser("hank", ipatest.User{Password: "Secret123!"})
	fake.AddGroup("dea", ipatest.Group{Members: []string{"hank"}})
	hy.seedConsentSession("hank", fakeConsentSession{ClientID: "lubelogger"})

	router.consentSweep()

	assert.Equal([]revokedConsent{{Subject: "walter", Client: "lubelogger"}}, hy.revokedConsents)
	assert.Equal([]string{"wiki"}, consentClients(hy, "walter"))
	assert.Equal([]string{"lubelogger"}, consentClients(hy, "hank"))
}

func TestConsentSweepInterval(t *testing.T) {
	assert := assert.New(t)
	_, router, _, _ := newConsentRevokeApp(t)
	assert.Equal(time.Hour, router.consentSweepInterval())

	viper.Set("hydra.consent_sweep_interval", "0")
	assert.Zero(router.consentSweepInterval())

	viper.Set("hydra.consent_sweep_interval", "1h")
	viper.Set("hydra.clients", []map[string]any{})
	assert.Zero(router.consentSweepInterval(), "no hydra.clients")

	viper.Set("hydra.default_deny", true)
	assert.Equal(time.Hour, router.consentSweepInterval(), "default_deny restricts every client")

	viper.Set("hydra.clients", "lubelogger")
	assert.Zero(router.consentSweepInterval(), "invalid hydra.clients must not revoke")

	_, plain, _ := newTestApp(t)
	viper.Set("hydra.default_deny", true)
	assert.Zero(plain.consentSweepInterval(), "hydra not configured")
}

func TestNextPageToken(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Link", `</admin/oauth2/auth/sessions/consent?page_size=250&page_token=abc>; rel="first",</admin/oauth2/auth/sessions/consent?page_size=250&page_token=def>; rel="next"`)
	assert.Equal(t, "def", nextPageToken(resp))
	assert.Equal(t, "", nextPageToken(&http.Response{Header: http.Header{}}))
	assert.Equal(t, "", nextPageToken(nil))
}
