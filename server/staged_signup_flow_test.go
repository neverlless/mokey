package server

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// stagedSignup posts the signup form (captcha disabled by the caller's config)
func stagedSignup(t *testing.T, app *fiber.App, username, email string) *testClient {
	t.Helper()
	tc := newTestClient(t, app)
	tc.getCSRF("/signup")
	resp := tc.postForm("/signup", url.Values{
		"username":  {username},
		"email":     {email},
		"first":     {"New"},
		"last":      {"User"},
		"password":  {"NewSecret456!"},
		"password2": {"NewSecret456!"},
	}, nil)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	return tc
}

func TestStagedSignupAndVerifyFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
		viper.Set("accounts.staged_signup", true)
	})

	tc := stagedSignup(t, app, "jesse", "jesse@example.com")

	// account lives in the staging tree only, invisible to active users
	su := fake.stageusers["jesse"]
	if assert.NotNil(su) {
		assert.Equal(UserCategoryUnverified, su.Category)
		assert.Equal("NewSecret456!", su.Password)
	}
	assert.Nil(fake.users["jesse"])

	// verify via emailed token: staged user is activated
	router.storage.Delete(TokenAccountVerify + TokenIssuedPrefix + "jesse")
	token, err := NewToken("jesse", "jesse@example.com", TokenAccountVerify, router.storage)
	assert.NoError(err)
	tc.getCSRF("/auth/verify/" + token)
	resp := tc.postForm("/auth/verify/"+token, url.Values{}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	assert.Nil(fake.stageusers["jesse"])
	u := fake.users["jesse"]
	if assert.NotNil(u) {
		assert.Equal("", u.Category)
		assert.False(u.Locked)
		// FreeIPA expires the password on activation; first login goes
		// through the existing expired-password change flow
		assert.True(u.Expired)
	}

	// verify token is single-use
	resp = tc.get("/auth/verify/" + token)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)
}

func TestStagedSignupAdminApproveFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
		viper.Set("accounts.staged_signup", true)
		viper.Set("accounts.require_admin_verify", true)
		viper.Set("admin.enabled", true)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: []string{"admins"}})

	verify := func(username, email string) {
		tc := stagedSignup(t, app, username, email)
		router.storage.Delete(TokenAccountVerify + TokenIssuedPrefix + username)
		token, err := NewToken(username, email, TokenAccountVerify, router.storage)
		assert.NoError(err)
		tc.getCSRF("/auth/verify/" + token)
		resp := tc.postForm("/auth/verify/"+token, url.Values{}, nil)
		assert.Equal(fiber.StatusOK, resp.StatusCode)
		assert.Contains(readBody(t, resp), "awaiting administrator approval")
	}

	verify("jesse", "jesse@example.com")
	verify("kim", "kim@example.com")

	// email verified: still staged, marked pending, no active account yet
	if assert.NotNil(fake.stageusers["jesse"]) {
		assert.Equal(UserCategoryPending, fake.stageusers["jesse"].Category)
	}
	assert.Nil(fake.users["jesse"])

	// admin sees both in the pending queue
	tcAdmin := newTestClient(t, app)
	tcAdmin.login("walter", "Secret123!")
	resp := tcAdmin.get("/admin/pending", htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)
	assert.Contains(body, "jesse")
	assert.Contains(body, "kim")

	// approve jesse: activated with expired password, category cleared
	resp = tcAdmin.postForm("/admin/user/approve", url.Values{"username": {"jesse"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Nil(fake.stageusers["jesse"])
	u := fake.users["jesse"]
	if assert.NotNil(u) {
		assert.Equal("", u.Category)
		assert.True(u.Expired)
	}

	// deny kim: staged registration is deleted, never became a real account
	resp = tcAdmin.postForm("/admin/user/deny", url.Values{"username": {"kim"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Nil(fake.stageusers["kim"])
	assert.Nil(fake.users["kim"])

	// approve is refused for accounts that are not pending
	resp = tcAdmin.postForm("/admin/user/approve", url.Values{"username": {"jesse"}}, htmx)
	assert.Equal(fiber.StatusInternalServerError, resp.StatusCode)
}

func TestStagedSignupVerifyResend(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
		viper.Set("accounts.staged_signup", true)
	})

	stagedSignup(t, app, "jesse", "jesse@example.com")
	assert.NotNil(fake.stageusers["jesse"])

	// signup issued a verify token; clear the issued marker so the resend
	// path can issue a fresh one
	router.storage.Delete(TokenAccountVerify + TokenIssuedPrefix + "jesse")

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/verify")
	resp := tc.postForm("/auth/verify", url.Values{"username": {"jesse"}}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// a fresh verify token was issued for the staged user
	issued, err := router.storage.Get(TokenAccountVerify + TokenIssuedPrefix + "jesse")
	assert.NoError(err)
	assert.NotEmpty(issued)
}

func TestStagedSignupDuplicateUsername(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
		viper.Set("accounts.staged_signup", true)
	})
	// active user with the same name: stageuser_add alone would not
	// conflict until activation, so signup must check the active tree
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/signup")
	resp := tc.postForm("/signup", url.Values{
		"username":  {"walter"},
		"email":     {"other@example.com"},
		"first":     {"Walter"},
		"last":      {"White"},
		"password":  {"NewSecret456!"},
		"password2": {"NewSecret456!"},
	}, nil)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	assert.Contains(readBody(t, resp), "already exists")
	assert.Nil(fake.stageusers["walter"])

	// staged user with the same name also conflicts
	stagedSignup(t, app, "gus", "gus@example.com")
	tc2 := newTestClient(t, app)
	tc2.getCSRF("/signup")
	resp = tc2.postForm("/signup", url.Values{
		"username":  {"gus"},
		"email":     {"gus2@example.com"},
		"first":     {"Gus"},
		"last":      {"Fring"},
		"password":  {"NewSecret456!"},
		"password2": {"NewSecret456!"},
	}, nil)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	assert.Contains(readBody(t, resp), "already exists")
}
