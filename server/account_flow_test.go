package server

import (
	"net/url"
	"regexp"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var captchaIDPattern = regexp.MustCompile(`name="captcha_id"[^>]*value="([^"]+)"`)

// getCaptcha fetches a page and returns (captchaID, solution)
func getCaptcha(t *testing.T, tc *testClient, path string) (string, string) {
	t.Helper()
	resp := tc.get(path)
	body := readBody(t, resp)
	m := captchaIDPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no captcha id found in %s", path)
	}
	return m[1], captchaSolution(t, m[1])
}

func TestSignupAndVerifyFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	tc := newTestClient(t, app)
	tc.getCSRF("/signup")
	captchaID, solution := getCaptcha(t, tc, "/signup")

	resp := tc.postForm("/signup", url.Values{
		"username":    {"jesse"},
		"email":       {"jesse@example.com"},
		"first":       {"Jesse"},
		"last":        {"Pinkman"},
		"password":    {"NewSecret456!"},
		"password2":   {"NewSecret456!"},
		"captcha_id":  {captchaID},
		"captcha_sol": {solution},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// account exists, disabled and marked unverified until email verification
	u := fake.users["jesse"]
	if assert.NotNil(u) {
		assert.True(u.Locked)
		assert.Equal(UserCategoryUnverified, u.Category)
		assert.Equal("NewSecret456!", u.Password)
	}

	// login before verification fails (locked)
	tcLogin := newTestClient(t, app)
	tcLogin.getCSRF("/auth/login")
	resp = tcLogin.postForm("/auth/login", url.Values{"username": {"jesse"}}, nil)
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)

	// verify via emailed token (built directly; SMTP is not under test —
	// signup already issued one, so clear the issued marker first)
	router.storage.Delete(TokenAccountVerify + TokenIssuedPrefix + "jesse")
	token, err := NewToken("jesse", "jesse@example.com", TokenAccountVerify, router.storage)
	assert.NoError(err)

	tc2 := newTestClient(t, app)
	resp = tc2.get("/auth/verify/" + token)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tc2.getCSRF("/auth/verify/" + token)

	resp = tc2.postForm("/auth/verify/"+token, url.Values{}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.False(fake.users["jesse"].Locked)
	assert.Equal("", fake.users["jesse"].Category)

	// verify token is single-use
	resp = tc2.get("/auth/verify/" + token)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)

	// now login works
	tcLogin2 := newTestClient(t, app)
	tcLogin2.login("jesse", "NewSecret456!")
}

func TestSignupDuplicateUsername(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/signup")
	captchaID, solution := getCaptcha(t, tc, "/signup")

	resp := tc.postForm("/signup", url.Values{
		"username":    {"walter"},
		"email":       {"other@example.com"},
		"first":       {"Walter"},
		"last":        {"White"},
		"password":    {"NewSecret456!"},
		"password2":   {"NewSecret456!"},
		"captcha_id":  {captchaID},
		"captcha_sol": {solution},
	}, nil)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	assert.Contains(readBody(t, resp), "already exists")
}

func TestSignupWrongCaptcha(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)

	tc := newTestClient(t, app)
	tc.getCSRF("/signup")
	captchaID, _ := getCaptcha(t, tc, "/signup")

	resp := tc.postForm("/signup", url.Values{
		"username":    {"jesse"},
		"email":       {"jesse@example.com"},
		"first":       {"Jesse"},
		"last":        {"Pinkman"},
		"password":    {"NewSecret456!"},
		"password2":   {"NewSecret456!"},
		"captcha_id":  {captchaID},
		"captcha_sol": {"000000"},
	}, nil)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	assert.Nil(fake.users["jesse"])
}

func TestSignupDisabled(t *testing.T) {
	assert := assert.New(t)
	// enable_signup=false must be set before routes are built
	fakePre := func() { viper.Set("accounts.enable_signup", false) }
	app, _, _ := newTestAppWith(t, fakePre)

	tc := newTestClient(t, app)
	resp := tc.get("/signup")
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)
}

func TestPasswordForgotIssuesToken(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/forgotpw")
	captchaID, solution := getCaptcha(t, tc, "/auth/forgotpw")

	resp := tc.postForm("/auth/forgotpw", url.Values{
		"username":    {"walter"},
		"captcha_id":  {captchaID},
		"captcha_sol": {solution},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// a reset token was issued for the user (email delivery not under test)
	issued, err := router.storage.Get(TokenPasswordReset + TokenIssuedPrefix + "walter")
	assert.NoError(err)
	assert.NotNil(issued)
}

func TestPasswordForgotUnknownUserSameResponse(t *testing.T) {
	assert := assert.New(t)
	app, router, _ := newTestApp(t)

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/forgotpw")
	captchaID, solution := getCaptcha(t, tc, "/auth/forgotpw")

	// unknown user gets the same success page — no user enumeration
	resp := tc.postForm("/auth/forgotpw", url.Values{
		"username":    {"nosuch"},
		"captcha_id":  {captchaID},
		"captcha_sol": {solution},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	issued, _ := router.storage.Get(TokenPasswordReset + TokenIssuedPrefix + "nosuch")
	assert.Nil(issued)
}

func TestAdminRouteGating(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: []string{"admins"}})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})

	// non-admin is rejected
	tcUser := newTestClient(t, app)
	tcUser.login("jesse", "Secret123!")
	resp := tcUser.postForm("/admin/user/block", url.Values{"username": {"walter"}}, htmx)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)

	// admin group member can act on users
	tcAdmin := newTestClient(t, app)
	tcAdmin.login("walter", "Secret123!")
	resp = tcAdmin.postForm("/admin/user/block", url.Values{"username": {"jesse"}}, htmx)
	assert.NotEqual(fiber.StatusForbidden, resp.StatusCode)
	assert.True(fake.users["jesse"].Locked)
}

func TestAdminDisabledByDefault(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	// even a member of the admins group is refused while admin.enabled=false
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: []string{"admins"}})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/admin/user/block", url.Values{"username": {"x"}}, htmx)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
}
