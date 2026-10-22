package server

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// newHydraTestApp builds the app with a fake Hydra admin API wired in.
// hydra.admin_url must be set before newFiber so the /oauth routes register.
func newHydraTestApp(t *testing.T) (*fiber.App, *fakeIPA, *fakeHydra) {
	t.Helper()
	hy := newFakeHydra()
	t.Cleanup(hy.Close)

	app, _, fake := newTestAppWith(t, func() {
		viper.Set("hydra.admin_url", hy.srv.URL)
		viper.Set("hydra.login_timeout", int64(3600))
	})
	return app, fake, hy
}

func TestOIDCLoginFlow(t *testing.T) {
	assert := assert.New(t)
	app, fake, hy := newHydraTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	hy.seedLogin("chal-1", "", false)

	tc := newTestClient(t, app)

	// hydra sends the browser to mokey with a login challenge; not logged
	// in and skip=false renders the login page carrying the challenge
	resp := tc.get("/oauth/login?login_challenge=chal-1")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), "chal-1")

	// authenticating with the challenge accepts the login request in hydra
	// and redirects the browser back to hydra
	tc.getCSRF("/auth/login")
	resp = tc.postForm("/auth/authenticate", url.Values{
		"username":  {"walter"},
		"password":  {"Secret123!"},
		"challenge": {"chal-1"},
	}, htmx)
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	assert.Equal("https://hydra.example.com/continue-login", resp.Header.Get("HX-Redirect"))

	assert.Equal([]string{"walter"}, hy.acceptedLogins)
	assert.Equal(int64(3600), hy.rememberDuration)
}

func TestOIDCLoginSkip(t *testing.T) {
	assert := assert.New(t)
	app, fake, hy := newHydraTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	hy.seedLogin("chal-2", "walter", true)

	tc := newTestClient(t, app)

	// hydra already has an authentication session: skip straight through
	resp := tc.get("/oauth/login?login_challenge=chal-2")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("https://hydra.example.com/continue-login", resp.Header.Get("Location"))
	assert.Equal([]string{"walter"}, hy.acceptedLogins)
}

func TestOIDCLoginMissingChallenge(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newHydraTestApp(t)

	tc := newTestClient(t, app)
	resp := tc.get("/oauth/login")
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
}

func TestOIDCConsentFlow(t *testing.T) {
	assert := assert.New(t)
	app, fake, hy := newHydraTestApp(t)
	fake.addUser("walter", &fakeUser{
		Password: "Secret123!",
		Email:    "walter@example.com",
		Groups:   []string{"admins"},
	})
	hy.seedConsent("consent-1", "walter")

	tc := newTestClient(t, app)
	resp := tc.get("/oauth/consent?consent_challenge=consent-1")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("https://hydra.example.com/continue-consent", resp.Header.Get("Location"))

	// the accepted consent carries the granted scopes and id_token claims
	if !assert.NotNil(hy.acceptedConsent) {
		return
	}
	scopes, _ := hy.acceptedConsent["grant_scope"].([]interface{})
	assert.Len(scopes, 2)
	session, _ := hy.acceptedConsent["session"].(map[string]interface{})
	idToken, _ := session["id_token"].(map[string]interface{})
	assert.Equal("walter", idToken["uid"])
	assert.Equal("walter@example.com", idToken["email"])
	assert.Equal([]interface{}{"admins"}, idToken["groups"])
}

func TestOIDCConsentRequiresMFA(t *testing.T) {
	assert := assert.New(t)
	app, fake, hy := newHydraTestApp(t)
	viper.Set("accounts.require_mfa", true)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"}) // no OTP
	hy.seedConsent("consent-2", "walter")

	tc := newTestClient(t, app)
	resp := tc.get("/oauth/consent?consent_challenge=consent-2")
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
	assert.Nil(hy.acceptedConsent)
}

func TestOIDCConsentClientGroups(t *testing.T) {
	// parsed from TOML so the test covers the real [[hydra.clients]] shape
	policies := `
[[hydra.clients]]
client_id = "lubelogger"
groups = ["lubelogger-users", "admins"]
`

	tests := []struct {
		name        string
		client      string
		groups      []string
		defaultDeny bool
		allowed     bool
	}{
		{"member of listed group", "lubelogger", []string{"ipausers", "lubelogger-users"}, false, true},
		{"group match ignores case", "lubelogger", []string{"Admins"}, false, true},
		{"not a member", "lubelogger", []string{"ipausers"}, false, false},
		{"unlisted client is open", "other-app", []string{"ipausers"}, false, true},
		{"unlisted client with default_deny", "other-app", []string{"lubelogger-users"}, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			app, fake, hy := newHydraTestApp(t)
			viper.SetConfigType("toml")
			if !assert.NoError(viper.MergeConfig(strings.NewReader(policies))) {
				return
			}
			viper.Set("hydra.default_deny", tt.defaultDeny)
			fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: tt.groups})
			hy.seedConsentForClient("consent-g", "walter", tt.client)

			tc := newTestClient(t, app)
			resp := tc.get("/oauth/consent?consent_challenge=consent-g")
			if tt.allowed {
				assert.Equal(fiber.StatusFound, resp.StatusCode)
				assert.NotNil(hy.acceptedConsent)
				assert.Nil(hy.rejectedConsent)
				return
			}

			// denied: rejected in Hydra, error shown by mokey, no redirect
			assert.Equal(fiber.StatusForbidden, resp.StatusCode)
			assert.Empty(resp.Header.Get("Location"))
			assert.Nil(hy.acceptedConsent)
			if assert.NotNil(hy.rejectedConsent) {
				assert.Equal("access_denied", hy.rejectedConsent["error"])
			}
		})
	}
}

func TestOIDCConsentInvalidClientPolicyDenies(t *testing.T) {
	assert := assert.New(t)
	app, fake, hy := newHydraTestApp(t)
	viper.Set("hydra.clients", "lubelogger")
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	hy.seedConsent("consent-bad", "walter")

	tc := newTestClient(t, app)
	resp := tc.get("/oauth/consent?consent_challenge=consent-bad")
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
	assert.Nil(hy.acceptedConsent)
	assert.NotNil(hy.rejectedConsent)
}

func TestOIDCLogoutFlow(t *testing.T) {
	assert := assert.New(t)
	app, fake, hy := newHydraTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	hy.seedLogout("logout-1", "walter")

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// hydra front-channel logout: destroys the session and redirects back
	resp := tc.get("/auth/logout?logout_challenge=logout-1")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("https://client.example.com/logged-out", resp.Header.Get("Location"))
	assert.Equal([]string{"logout-1"}, hy.acceptedLogouts)

	// local session is gone
	resp = tc.get("/")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
}

func TestLogoutRevokesHydraSessions(t *testing.T) {
	assert := assert.New(t)
	app, fake, hy := newHydraTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// a normal UI logout also revokes the user's hydra login sessions
	resp := tc.postForm("/auth/logout", url.Values{}, nil)
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal([]string{"walter"}, hy.revokedSubjects)
}
