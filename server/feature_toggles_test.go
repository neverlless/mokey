package server

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// #27: some deployments do not want users doing group self-service or
// poking at HBAC rules. Hiding the tab is not enough — the routes behind
// them have to be gone too.
func TestGroupsAndAccessCanBeDisabled(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_groups", false)
		viper.Set("accounts.enable_access", false)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	body := readBody(t, tc.get("/account"))
	assert.NotContains(body, `href="/groups"`)
	assert.NotContains(body, `href="/access"`)

	for _, path := range []string{"/groups", "/access"} {
		resp := tc.get(path)
		assert.Equal(fiber.StatusNotFound, resp.StatusCode, "GET %s", path)
	}

	tc.getCSRF("/account")
	for _, path := range []string{"/access/test", "/groups/request", "/groups/leave",
		"/groups/approve", "/groups/deny", "/groups/remove-member"} {
		resp := tc.postForm(path, url.Values{}, htmx)
		assert.Equal(fiber.StatusNotFound, resp.StatusCode, "POST %s", path)
	}
}

// both stay on by default
func TestGroupsAndAccessEnabledByDefault(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	body := readBody(t, tc.get("/account"))
	assert.Contains(body, `href="/groups"`)
	assert.Contains(body, `href="/access"`)
	assert.Equal(fiber.StatusOK, tc.get("/groups").StatusCode)
	assert.Equal(fiber.StatusOK, tc.get("/access").StatusCode)
}
