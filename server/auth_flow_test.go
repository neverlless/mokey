package server

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLoginSuccess(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	// step 1: username check renders the password form
	resp := tc.postForm("/auth/login", url.Values{"username": {"walter"}}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), "walter")

	// step 2: authenticate
	resp = tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"Secret123!"},
	}, nil)
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	assert.Equal("/", resp.Header.Get("HX-Redirect"))

	// authenticated session reaches the account page
	resp = tc.get("/")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}

func TestLoginWrongPassword(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	resp := tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"wrong"},
	}, nil)
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)

	// still not logged in
	resp = tc.get("/")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("/auth/login", resp.Header.Get("Location"))
}

func TestLoginUnknownUser(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	resp := tc.postForm("/auth/login", url.Values{"username": {"nosuch"}}, nil)
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
}

func TestLoginHideInvalidUsername(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	viper.Set("accounts.hide_invalid_username_error", true)
	viper.Set("accounts.block_users", []string{"gus"})
	fake.addUser("skyler", &fakeUser{Password: "Secret123!", Locked: true})
	fake.addUser("gus", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	// unknown, locked, and blocked users all get the same password form —
	// no user enumeration on the username step
	for _, username := range []string{"nosuch", "skyler", "gus"} {
		resp := tc.postForm("/auth/login", url.Values{"username": {username}}, nil)
		assert.Equal(fiber.StatusOK, resp.StatusCode, username)
		assert.NotContains(readBody(t, resp), "locked", username)
	}

	// and the authenticate step rejects them uniformly even with the right
	// password
	for _, username := range []string{"skyler", "gus"} {
		resp := tc.postForm("/auth/authenticate", url.Values{
			"username": {username},
			"password": {"Secret123!"},
		}, nil)
		assert.Equal(fiber.StatusUnauthorized, resp.StatusCode, username)
		assert.Equal(readBody(t, resp), T("account.invalid_credentials"), username)
	}
}

func TestLoginBlockedUser(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	viper.Set("accounts.block_users", []string{"walter"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	resp := tc.postForm("/auth/login", url.Values{"username": {"walter"}}, nil)
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)

	resp = tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"Secret123!"},
	}, nil)
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
}

func TestLoginLockedUser(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Locked: true})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	resp := tc.postForm("/auth/login", url.Values{"username": {"walter"}}, nil)
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
	assert.Contains(readBody(t, resp), "locked")
}

func TestCSRFRequiredOnPost(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.get("/auth/login") // establish session, but don't capture the token

	resp := tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"Secret123!"},
	}, nil)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
}

func TestCSRFWrongToken(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")
	tc.csrf = "forged-token"

	resp := tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"Secret123!"},
	}, nil)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
}

func TestLogout(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/auth/logout", url.Values{}, nil)
	assert.Equal(fiber.StatusFound, resp.StatusCode)

	resp = tc.get("/")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("/auth/login", resp.Header.Get("Location"))
}

func TestLogoutGETDoesNotDestroySession(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// CSRF-exempt GET (e.g. <img src="/auth/logout"> on a hostile page)
	// must not log the user out; only the Hydra logout_challenge path may
	resp := tc.get("/auth/logout")
	assert.Equal(fiber.StatusFound, resp.StatusCode)

	resp = tc.get("/")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}

func TestExpiredPasswordFlow(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "OldSecret123!", Expired: true})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	// login with expired password renders the forced-change form
	resp := tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"OldSecret123!"},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), "expired")

	// change the expired password; non-OTP users are auto-logged-in
	resp = tc.postForm("/auth/expiredpw", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
	}, nil)
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	assert.Equal("/", resp.Header.Get("HX-Redirect"))

	resp = tc.get("/")
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// old password no longer works
	tc2 := newTestClient(t, app)
	tc2.getCSRF("/auth/login")
	resp = tc2.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"OldSecret123!"},
	}, nil)
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)

	// new password works
	tc2.login("walter", "NewSecret456!")
}

func TestExpiredPasswordFlowRequiresPriorLoginAttempt(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "OldSecret123!", Expired: true})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	// hitting expiredpw without the expired-login session state redirects away
	resp := tc.postForm("/auth/expiredpw", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
	}, nil)
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("/auth/login", resp.Header.Get("Location"))
	// password unchanged
	assert.Equal("OldSecret123!", fake.users["walter"].Password)
}

func TestExpiredPasswordOTPUserNoAutoLogin(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{
		Password:  "OldSecret123!",
		Expired:   true,
		AuthTypes: []string{"otp"},
	})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	resp := tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"OldSecret123!"},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// OTP-only user changing an expired password is sent back to login, not
	// auto-logged-in (the just-used TOTP code would be a replay — ubccr#127)
	resp = tc.postForm("/auth/expiredpw", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
		"otp":          {"123456"},
	}, nil)
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	assert.Equal("/auth/login", resp.Header.Get("HX-Redirect"))

	// not logged in
	resp = tc.get("/")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
}

func TestSecureHeadersPresent(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)

	tc := newTestClient(t, app)
	resp := tc.get("/auth/login")

	assert.Equal("DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal("nosniff", resp.Header.Get("X-Content-Type-Options"))
	csp := resp.Header.Get("Content-Security-Policy")
	assert.True(strings.Contains(csp, "default-src 'self'"))
	assert.NotContains(csp, "script-src 'self' 'unsafe-inline'")
	assert.Contains(csp, "script-src 'self' 'nonce-")
	assert.Equal("no-store", resp.Header.Get("Cache-Control"))
}

var cspNoncePattern = regexp.MustCompile(`'nonce-([^']+)'`)

func TestCSPNonceMatchesInlineScripts(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)

	tc := newTestClient(t, app)
	resp := tc.get("/signup")

	m := cspNoncePattern.FindStringSubmatch(resp.Header.Get("Content-Security-Policy"))
	if !assert.NotNil(m, "no nonce in CSP header") {
		return
	}
	nonce := m[1]

	body := readBody(t, resp)
	assert.Contains(body, `<script nonce="`+nonce+`">`)
	// every inline script on the page must carry the nonce
	assert.NotContains(body, "<script>")

	// nonce is fresh per request
	resp = tc.get("/signup")
	m2 := cspNoncePattern.FindStringSubmatch(resp.Header.Get("Content-Security-Policy"))
	assert.NotEqual(nonce, m2[1])
}

func TestHSTSOnHTTPS(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestAppWith(t, func() {
		viper.Set("server.trusted_proxies", []string{"0.0.0.0"})
	})

	tc := newTestClient(t, app)

	// plain http: no HSTS
	resp := tc.get("/auth/login")
	assert.Empty(resp.Header.Get("Strict-Transport-Security"))

	// https via trusted proxy: HSTS present
	resp = tc.get("/auth/login", map[string]string{"X-Forwarded-Proto": "https"})
	assert.Equal("max-age=31536000", resp.Header.Get("Strict-Transport-Security"))
}

func TestHealthzNoAuth(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)

	tc := newTestClient(t, app)
	resp := tc.get("/healthz")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}
