package server

import (
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var htmx = map[string]string{"HX-Request": "true"}

func TestPasswordChange(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "OldSecret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "OldSecret123!")

	resp := tc.postForm("/password/change", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.NotContains(readBody(t, resp), "fatal")
	assert.Equal("NewSecret456!", fake.users["walter"].Password)

	// the changing session survives
	resp = tc.get("/")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}

func TestPasswordChangeWrongCurrent(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "OldSecret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "OldSecret123!")

	resp := tc.postForm("/password/change", url.Values{
		"password":     {"wrong-current"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("OldSecret123!", fake.users["walter"].Password)
}

func TestPasswordChangeMismatchedConfirm(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "OldSecret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "OldSecret123!")

	resp := tc.postForm("/password/change", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"Different789!"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("OldSecret123!", fake.users["walter"].Password)
}

func TestPasswordChangeInvalidatesOtherSessions(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "OldSecret123!"})

	// two browser sessions
	tc1 := newTestClient(t, app)
	tc1.login("walter", "OldSecret123!")
	tc2 := newTestClient(t, app)
	tc2.login("walter", "OldSecret123!")

	// tc1 changes the password
	resp := tc1.postForm("/password/change", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("NewSecret456!", fake.users["walter"].Password)

	// the change wrote an invalidation marker
	marker, err := router.storage.Get(PasswordChangedPrefix + "walter")
	assert.NoError(err)
	assert.NotNil(marker)

	// Marker resolution is 1 second and everything above happened within the
	// same second, so both sessions survive right now (documented ceiling of
	// the mechanism; evaluation logic is unit-tested in auth_test.go). The
	// changing session must survive its own change:
	resp = tc1.get("/")
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// Simulate the change having happened a later second: sessions from
	// before the marker are logged out on their next request
	futureMarker(t, router, "walter")
	resp = tc2.get("/")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("/auth/login", resp.Header.Get("Location"))
}

func TestPasswordChangeRequiresLogin(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/login")

	resp := tc.postForm("/password/change", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
	}, htmx)
	// redirectLogin for htmx requests: 204 + HX-Redirect
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	assert.Equal("/auth/login", resp.Header.Get("HX-Redirect"))
}

func TestPasswordResetFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "OldSecret123!"})

	token, err := NewToken("walter", "walter@example.com", TokenPasswordReset, router.storage)
	assert.NoError(err)

	tc := newTestClient(t, app)

	resp := tc.get("/auth/resetpw/" + token)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tc.getCSRF("/auth/resetpw/" + token)

	resp = tc.postForm("/auth/resetpw/"+token, url.Values{
		"password":  {"NewSecret456!"},
		"password2": {"NewSecret456!"},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("NewSecret456!", fake.users["walter"].Password)

	// token is single-use
	resp = tc.get("/auth/resetpw/" + token)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)

	// user can login with the new password
	tc2 := newTestClient(t, app)
	tc2.login("walter", "NewSecret456!")
}

func TestPasswordResetGarbageToken(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)

	tc := newTestClient(t, app)
	resp := tc.get("/auth/resetpw/garbage-token")
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)
}

func TestPasswordResetLockedUser(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "OldSecret123!", Locked: true})

	token, err := NewToken("walter", "walter@example.com", TokenPasswordReset, router.storage)
	assert.NoError(err)

	tc := newTestClient(t, app)
	resp := tc.get("/auth/resetpw/" + token)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)
}

func TestPasswordResetInvalidatesSessions(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "OldSecret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "OldSecret123!")

	token, err := NewToken("walter", "walter@example.com", TokenPasswordReset, router.storage)
	assert.NoError(err)

	tc2 := newTestClient(t, app)
	tc2.getCSRF("/auth/resetpw/" + token)
	resp := tc2.postForm("/auth/resetpw/"+token, url.Values{
		"password":  {"NewSecret456!"},
		"password2": {"NewSecret456!"},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// reset wrote an invalidation marker; with the marker a second later
	// than the login, the pre-reset session is logged out
	marker, err := router.storage.Get(PasswordChangedPrefix + "walter")
	assert.NoError(err)
	assert.NotNil(marker)
	futureMarker(t, router, "walter")

	resp = tc.get("/")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
}

// futureMarker rewrites the password-change marker one minute into the
// future, standing in for time passing between login and password change —
// the marker has 1-second resolution and flow tests run inside one second.
func futureMarker(t *testing.T, router *Router, username string) {
	t.Helper()
	future := []byte(strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
	if err := router.storage.Set(PasswordChangedPrefix+username, future, time.Hour); err != nil {
		t.Fatalf("failed to set marker: %s", err)
	}
}

// #19: the policy is shown on the GET form but vanished on the POST
// re-render, exactly when the user needs it to fix a rejected password
func TestPasswordChangePolicyVisibleOnError(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// baseline: the policy renders on the form itself
	resp := tc.get("/password/change", htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), T("password.policy_title"))

	// and must still render when the submission is rejected
	resp = tc.postForm("/password/change", url.Values{
		"password":     {"Secret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"Mismatch789!"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), T("password.policy_title"))
}

// #16: mokey validated new passwords against its own accounts.min_passwd_*
// config, which silently drifts from the policy FreeIPA actually enforces.
// Staged signup made that visible: stageuser_add applies no password policy,
// so a password FreeIPA would reject sailed through registration.
func TestSignupEnforcesFreeIPAPasswordPolicy(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
		// laxer than the fake FreeIPA policy (8 chars, 2 classes)
		viper.Set("accounts.min_passwd_len", 4)
		viper.Set("accounts.min_passwd_classes", 1)
	})

	tc := newTestClient(t, app)
	tc.getCSRF("/signup")

	// 7 chars, one class: allowed by mokey's config, rejected by FreeIPA
	resp := tc.postForm("/signup", url.Values{
		"username":  {"jesse"},
		"email":     {"jesse@example.com"},
		"first":     {"Jesse"},
		"last":      {"Pinkman"},
		"password":  {"abcdefg"},
		"password2": {"abcdefg"},
	}, nil)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	assert.Nil(fake.users["jesse"], "account must not be created with a policy-violating password")

	// a password meeting the FreeIPA policy still works
	tc.getCSRF("/signup")
	resp = tc.postForm("/signup", url.Values{
		"username":  {"jesse"},
		"email":     {"jesse@example.com"},
		"first":     {"Jesse"},
		"last":      {"Pinkman"},
		"password":  {"abcdefg1"},
		"password2": {"abcdefg1"},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.NotNil(fake.users["jesse"])
}
