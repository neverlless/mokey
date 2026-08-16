package server

import (
	"net/url"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestOTPTokenLifecycle(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// add: server creates the token and shows the QR code
	resp := tc.postForm("/otptoken/add", url.Values{"desc": {"phone"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	if !assert.Len(fake.tokens, 1) {
		return
	}
	tok := fake.tokens[0]
	assert.Equal("walter", tok.Owner)

	// verify with a real TOTP code computed from the secret
	code, err := totp.GenerateCode(tok.Secret, time.Now())
	assert.NoError(err)
	resp = tc.postForm("/otptoken/verify", url.Values{
		"otpcode": {code},
		"uri":     {tok.uri()},
		"uuid":    {tok.UUID},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// list shows the token
	resp = tc.get("/otptoken/list", htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// disable / enable / remove
	resp = tc.postForm("/otptoken/disable", url.Values{"uuid": {tok.UUID}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.True(fake.tokens[0].Disabled)

	resp = tc.postForm("/otptoken/enable", url.Values{"uuid": {tok.UUID}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.False(fake.tokens[0].Disabled)

	resp = tc.postForm("/otptoken/remove", url.Values{"uuid": {tok.UUID}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Len(fake.tokens, 0)
}

func TestOTPTokenVerifyWrongCode(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/add", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tok := fake.tokens[0]

	resp = tc.postForm("/otptoken/verify", url.Values{
		"otpcode": {"000000"},
		"uri":     {tok.uri()},
		"uuid":    {tok.UUID},
	}, htmx)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
}

func TestOTPTokenVerifyCancelRemovesToken(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/add", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tok := fake.tokens[0]

	resp = tc.postForm("/otptoken/verify", url.Values{
		"action": {"cancel"},
		"uri":    {tok.uri()},
		"uuid":   {tok.UUID},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Len(fake.tokens, 0)
}

func TestOTPRemoveLastActiveTokenBlocked(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{
		Password:  "Secret123!",
		AuthTypes: []string{"otp"},
	})
	fake.tokens = append(fake.tokens, &fakeOTPToken{
		UUID:   "11111111-2222-3333-4444-555555555555",
		Owner:  "walter",
		Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
	})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/remove", url.Values{
		"uuid": {"11111111-2222-3333-4444-555555555555"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), "last active token")
	assert.Len(fake.tokens, 1)
}

func TestOTPAutoMFAEnable(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.require_mfa", true)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/add", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tok := fake.tokens[0]

	code, err := totp.GenerateCode(tok.Secret, time.Now())
	assert.NoError(err)
	resp = tc.postForm("/otptoken/verify", url.Values{
		"otpcode": {code},
		"uri":     {tok.uri()},
		"uuid":    {tok.UUID},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// verifying the first token under require_mfa flips the account to
	// OTP-only auth
	assert.Equal([]string{"otp"}, fake.users["walter"].AuthTypes)
}

func TestAdminUserList(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: []string{"admins"}})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.get("/admin/users", htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)
	assert.Contains(body, "walter")
	assert.Contains(body, "jesse")
}

func TestAdminAuditList(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: []string{"admins"}})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.get("/admin/audit", htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}

func TestRateLimitOnAuthPosts(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("server.rate_limit_max", 3)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	form := url.Values{"username": {"walter"}, "password": {"wrong"}}
	for i := 0; i < 3; i++ {
		resp := tc.postForm("/auth/authenticate", form, nil)
		assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
	}

	resp := tc.postForm("/auth/authenticate", form, nil)
	assert.Equal(fiber.StatusTooManyRequests, resp.StatusCode)
}
