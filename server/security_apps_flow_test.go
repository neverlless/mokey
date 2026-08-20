package server

import (
	"net/url"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestConnectedAppsList(t *testing.T) {
	assert := assert.New(t)
	app, fake, hy := newHydraTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	hy.seedConsentSession("walter", fakeConsentSession{
		ClientID: "app-1", ClientName: "Example App", Scope: []string{"openid", "profile"},
		HandledAt: time.Now().Format(time.RFC3339),
	})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	body := securityPage(t, tc)
	assert.Contains(body, "Example App")
	assert.Contains(body, "profile")
	assert.Contains(body, "granted")
}

func TestConnectedAppsRevoke(t *testing.T) {
	assert := assert.New(t)
	app, fake, hy := newHydraTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	hy.seedConsentSession("walter", fakeConsentSession{ClientID: "app-1", ClientName: "Example App"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/security/apps/revoke", url.Values{"client": {"app-1"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.NotContains(readBody(t, resp), "Example App")

	assert.Equal([]revokedConsent{{Subject: "walter", Client: "app-1"}}, hy.revokedConsents)
	assert.Empty(hy.consentSessions["walter"])
}

func TestConnectedAppsAbsentWithoutHydra(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.get("/security/settings", htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}

// TestAppRevokeRouteAbsentWithoutHydra guards against a nil r.hydraClient
// dereference: the route must not exist at all on a Hydra-less deployment,
// mirroring the /oauth/* routes' registration gating.
func TestAppRevokeRouteAbsentWithoutHydra(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/security/apps/revoke", url.Values{"client": {"app-1"}}, htmx)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)
}
