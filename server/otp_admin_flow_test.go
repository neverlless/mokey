package server

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/neverlless/goipa/ipatest"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestOTPTokenLifecycle(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// add: server creates the token and shows the QR code
	resp := tc.postForm("/otptoken/add", url.Values{"desc": {"phone"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tok := scannedToken(t, readBody(t, resp))
	if !assert.Len(fake.OTPTokens(""), 1) {
		return
	}
	stored := fake.OTPTokens("")[0]
	assert.Equal("walter", stored.Owner)

	// notBefore must be sent as UTC — a local timestamp makes the token
	// reject codes until the timezone offset elapses (ubccr#159)
	assert.WithinDuration(time.Now().UTC(), stored.NotBefore, time.Minute)

	// verify with a real TOTP code computed from the secret
	code, err := totp.GenerateCode(tok.secret, time.Now())
	assert.NoError(err)
	resp = tc.postForm("/otptoken/verify", url.Values{
		"otpcode": {code},
		"uri":     {tok.uri},
		"uuid":    {tok.uuid},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// list shows the token
	resp = tc.get("/otptoken/list", htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// disable / enable / remove
	resp = tc.postForm("/otptoken/disable", url.Values{"uuid": {tok.uuid}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.True(fake.OTPTokens("")[0].Disabled)

	resp = tc.postForm("/otptoken/enable", url.Values{"uuid": {tok.uuid}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.False(fake.OTPTokens("")[0].Disabled)

	resp = tc.postForm("/otptoken/remove", url.Values{"uuid": {tok.uuid}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Len(fake.OTPTokens(""), 0)
}

var scanInputPattern = regexp.MustCompile(`name="(uuid|uri)" value="([^"]*)"`)

type scanned struct{ uuid, uri, secret string }

// scannedToken reads the token the scan dialog posts back to /otptoken/verify
func scannedToken(t *testing.T, body string) scanned {
	t.Helper()
	var tok scanned
	for _, m := range scanInputPattern.FindAllStringSubmatch(body, -1) {
		if m[1] == "uuid" {
			tok.uuid = html.UnescapeString(m[2])
		} else {
			tok.uri = html.UnescapeString(m[2])
		}
	}
	u, err := url.Parse(tok.uri)
	if err != nil || tok.uuid == "" {
		t.Fatalf("no token in the scan dialog: uuid %q, uri %q", tok.uuid, tok.uri)
	}
	tok.secret = u.Query().Get("secret")
	return tok
}

func TestOTPTokenVerifyWrongCode(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/add", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tok := scannedToken(t, readBody(t, resp))

	resp = tc.postForm("/otptoken/verify", url.Values{
		"otpcode": {"000000"},
		"uri":     {tok.uri},
		"uuid":    {tok.uuid},
	}, htmx)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
}

func TestOTPTokenVerifyCancelRemovesToken(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/add", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tok := scannedToken(t, readBody(t, resp))

	resp = tc.postForm("/otptoken/verify", url.Values{
		"action": {"cancel"},
		"uri":    {tok.uri},
		"uuid":   {tok.uuid},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Len(fake.OTPTokens(""), 0)
}

func TestOTPRemoveLastActiveTokenBlocked(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{
		Password:  "Secret123!",
		AuthTypes: []string{"otp"},
	})
	fake.AddOTPToken(ipatest.OTPToken{
		UUID:  "11111111-2222-3333-4444-555555555555",
		Owner: "walter",
	})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/remove", url.Values{
		"uuid": {"11111111-2222-3333-4444-555555555555"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), "last active token")
	assert.Len(fake.OTPTokens(""), 1)
}

func TestOTPAutoMFAEnable(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.require_mfa", true)
	})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/add", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tok := scannedToken(t, readBody(t, resp))

	code, err := totp.GenerateCode(tok.secret, time.Now())
	assert.NoError(err)
	resp = tc.postForm("/otptoken/verify", url.Values{
		"otpcode": {code},
		"uri":     {tok.uri},
		"uuid":    {tok.uuid},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// verifying the first token under require_mfa flips the account to
	// OTP-only auth
	assert.Equal([]string{"otp"}, fakeUser(fake, "walter").AuthTypes)
}

func TestOTPReadonlyGroup(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.otp_readonly_groups", []string{"hw-token-users"})
	})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"hw-token-users"}})
	fake.AddUser("jesse", ipatest.User{Password: "Secret123!"})

	// read-only user: list works, shows the notice, mutations are 403
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.get("/otptoken/list", htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), "managed by your administrator")

	resp = tc.postForm("/otptoken/add", url.Values{}, htmx)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
	assert.Len(fake.OTPTokens(""), 0)

	resp = tc.get("/otptoken/modal", htmx)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)

	// user outside the group is unaffected
	tc2 := newTestClient(t, app)
	tc2.login("jesse", "Secret123!")
	resp = tc2.postForm("/otptoken/add", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Len(fake.OTPTokens(""), 1)
}

func TestAdminUserList(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
	})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"admins"}})
	fake.AddUser("jesse", ipatest.User{Password: "Secret123!"})

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
	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"admins"}})

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
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

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

func TestRateLimitNotBypassedBySpoofedXFF(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("server.rate_limit_max", 3)
	})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	// rotating X-Forwarded-For must not reset the limiter: without a
	// configured trusted proxy the header is ignored
	form := url.Values{"username": {"walter"}, "password": {"wrong"}}
	for i := 0; i < 3; i++ {
		resp := tc.postForm("/auth/authenticate", form, map[string]string{
			"X-Forwarded-For": fmt.Sprintf("1.2.3.%d", i),
		})
		assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
	}

	resp := tc.postForm("/auth/authenticate", form, map[string]string{
		"X-Forwarded-For": "9.9.9.9",
	})
	assert.Equal(fiber.StatusTooManyRequests, resp.StatusCode)
}

// #20: cancelling out of the QR dialog is a deliberate act, not a failure —
// it used to share a branch with "the token URI would not parse" and left
// the user staring at "Failed to verify token."
func TestOTPTokenVerifyCancelIsNotAnError(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/add", url.Values{"desc": {"phone"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tok := scannedToken(t, readBody(t, resp))
	if !assert.Len(fake.OTPTokens(""), 1) {
		return
	}

	resp = tc.postForm("/otptoken/verify", url.Values{
		"action": {"cancel"},
		"uri":    {tok.uri},
		"uuid":   {tok.uuid},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	body := readBody(t, resp)
	assert.NotContains(body, T("otptoken.failed_to_verify_token"))
	// the unverified token is still cleaned up
	assert.Empty(fake.OTPTokens(""))
}

// a token URI mokey cannot parse really is a failure and must still say so
func TestOTPTokenVerifyUnparsableURIStillFails(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/otptoken/add", url.Values{"desc": {"phone"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	if !assert.Len(fake.OTPTokens(""), 1) {
		return
	}

	resp = tc.postForm("/otptoken/verify", url.Values{
		"uri":  {"otpauth://totp/%zz"}, // invalid percent-encoding: url.Parse fails
		"uuid": {fake.OTPTokens("")[0].UUID},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), T("otptoken.failed_to_verify_token"))
}
