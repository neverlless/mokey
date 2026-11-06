package server

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// HEAD must reach the GET route itself, not the catch-all 404, and health
// probes must not create sessions
func TestHeadFollowsGetRoute(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)
	tc := newTestClient(t, app)

	resp := tc.do(httptest.NewRequest(fiber.MethodHead, "/healthz", nil))
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Empty(resp.Header.Get("Set-Cookie"))

	resp = tc.do(httptest.NewRequest(fiber.MethodHead, "/auth/login", nil))
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}

func TestStaticAssets(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)
	tc := newTestClient(t, app)

	resp := tc.get("/static/css/style.css")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("public, max-age=900", resp.Header.Get("Cache-Control"))
	assert.Empty(resp.Header.Get("Last-Modified"))

	for _, path := range []string{"/static", "/static/", "/static/css", "/static/css/"} {
		resp := tc.get(path)
		assert.Equal(fiber.StatusNotFound, resp.StatusCode, path)
		assert.NotEmpty(resp.Header.Get("Content-Security-Policy"), path)
		assert.Equal("DENY", resp.Header.Get("X-Frame-Options"), path)
	}
}

func TestNavSection(t *testing.T) {
	for in, want := range map[string]string{
		"account": "account", "password": "security", "otp": "security", "passkey": "security",
		"security": "security", "admin": "admin", "admin/people": "people", "admin/log": "log",
		"groups": "groups",
	} {
		assert.Equal(t, want, navSection(in), in)
	}
}

func TestNavMarksCurrentSection(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	body := readBody(t, tc.get("/otp"))
	assert.Regexp(`<a[^>]*id="security-tab"[^>]*aria-current="page"|<a[^>]*aria-current="page"[^>]*id="security-tab"`, body)
	assert.NotContains(body, `id="admin-tab"`)
	assert.Contains(body, `id="otp-tab"`)
}

func TestNavHidesEmptyAccessGroup(t *testing.T) {
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_groups", false)
		viper.Set("accounts.enable_access", false)
		viper.Set("accounts.enable_apps", false)
	})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	assert.NotContains(t, readBody(t, tc.get("/account")), T("nav.group_access"))
}
