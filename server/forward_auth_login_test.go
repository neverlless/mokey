package server

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/stretchr/testify/assert"
)

const faContinueTarget = "/forward-auth/continue?p=fa-pending-abc"

// faContinueClient signs in through the real app; continueGet hits a
// stand-in /forward-auth/continue route sharing its session store, since
// routes cannot be added once the real app is built
type faContinueClient struct {
	*testClient
	stand *fiber.App
}

func newFAContinueClient(t *testing.T) (*faContinueClient, *ipatest.Server) {
	t.Helper()
	app, r, fake := newTestApp(t)
	stand := fiber.New()
	stand.Get("/forward-auth/continue", r.RequireLogin, func(c fiber.Ctx) error {
		return c.SendString("continue")
	})
	return &faContinueClient{testClient: newTestClient(t, app), stand: stand}, fake
}

func (tc *faContinueClient) continueGet() *http.Response {
	real := tc.app
	tc.app = tc.stand
	defer func() { tc.app = real }()
	return tc.get(faContinueTarget)
}

func TestSafeNextPath(t *testing.T) {
	for in, want := range map[string]string{
		"/":                             "/",
		faContinueTarget:                faContinueTarget,
		"/account":                      "/account",
		"":                              "/",
		"//evil.example.com":            "/",
		"https://evil.example.com":      "/",
		"/\\evil.example.com":           "/",
		"/ok\\x":                        "/",
		"evil":                          "/",
		"/a\nb":                         "/",
		"/a\x7fb":                       "/",
		"javascript:alert(1)":           "/",
		"/%2F%2Fevil.example.com":       "/%2F%2Fevil.example.com",
		"/x?u=https://evil.example.com": "/x?u=https://evil.example.com",
	} {
		assert.Equal(t, want, safeNextPath(in), "%q", in)
	}
}

func TestLoginReturnsToForwardAuthContinue(t *testing.T) {
	assert := assert.New(t)
	tc, fake := newFAContinueClient(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	resp := tc.continueGet()
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("/auth/login", resp.Header.Get("Location"))

	tc.getCSRF("/auth/login")
	resp = tc.postForm("/auth/login", url.Values{"username": {"walter"}}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	resp = tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"Secret123!"},
	}, nil)
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	assert.Equal(faContinueTarget, resp.Header.Get("HX-Redirect"))

	resp = tc.continueGet()
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("continue", readBody(t, resp))

}

func TestLoginReturnWithOTP(t *testing.T) {
	assert := assert.New(t)
	tc, fake := newFAContinueClient(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!" + "123456", AuthTypes: []string{"otp"}})

	tc.continueGet()
	tc.getCSRF("/auth/login")
	resp := tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"Secret123!"},
		"otp":      {"123456"},
	}, nil)
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	assert.Equal(faContinueTarget, resp.Header.Get("HX-Redirect"))
}

func TestLoginReturnAfterExpiredPassword(t *testing.T) {
	assert := assert.New(t)
	tc, fake := newFAContinueClient(t)
	fake.AddUser("walter", ipatest.User{Password: "OldSecret123!", PasswdExpire: time.Now()})

	tc.continueGet()
	tc.getCSRF("/auth/login")
	resp := tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"OldSecret123!"},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	resp = tc.postForm("/auth/expiredpw", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
	}, nil)
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	assert.Equal(faContinueTarget, resp.Header.Get("HX-Redirect"))
}

func TestLoginNextOnlyForForwardAuthContinue(t *testing.T) {
	assert := assert.New(t)
	tc, fake := newFAContinueClient(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc.get("/account")
	tc.getCSRF("/auth/login")
	resp := tc.postForm("/auth/authenticate", url.Values{
		"username": {"walter"},
		"password": {"Secret123!"},
	}, nil)
	assert.Equal("/", resp.Header.Get("HX-Redirect"))
}

func TestLoginNextRejectsUnsafeTargets(t *testing.T) {
	_, r, _ := newTestApp(t)
	for _, next := range []string{"//evil.example.com", "https://evil.example.com", "/\\evil.example.com"} {
		app := fiber.New()
		app.Get("/set", func(c fiber.Ctx) error {
			r.setLoginNext(c, next)
			return nil
		})
		app.Get("/take", func(c fiber.Ctx) error {
			return c.SendString(takeAndSave(t, r, c))
		})
		tc := newTestClient(t, app)
		tc.get("/set")
		assert.Equal(t, "/", readBody(t, tc.get("/take")), next)
	}
}

func TestLoginNextIsTakenOnce(t *testing.T) {
	_, r, _ := newTestApp(t)
	app := fiber.New()
	app.Get("/set", func(c fiber.Ctx) error {
		r.setLoginNext(c, faContinueTarget)
		return nil
	})
	app.Get("/take", func(c fiber.Ctx) error {
		return c.SendString(takeAndSave(t, r, c))
	})
	tc := newTestClient(t, app)
	tc.get("/set")
	assert.Equal(t, faContinueTarget, readBody(t, tc.get("/take")))
	assert.Equal(t, "/", readBody(t, tc.get("/take")))
}

func takeAndSave(t *testing.T, r *Router, c fiber.Ctx) string {
	sess, err := r.session(c)
	if err != nil {
		t.Fatal(err)
	}
	next := takeLoginNext(sess)
	if err := r.sessionSave(c, sess); err != nil {
		t.Fatal(err)
	}
	return next
}

func TestLoginReturnAfterExpiredPasswordWithOTP(t *testing.T) {
	assert := assert.New(t)
	tc, fake := newFAContinueClient(t)
	fake.AddUser("walter", ipatest.User{Password: "OldSecret123!", PasswdExpire: time.Now(), AuthTypes: []string{"otp"}})

	tc.continueGet()
	tc.getCSRF("/auth/login")
	tc.postForm("/auth/authenticate", url.Values{"username": {"walter"}, "password": {"OldSecret123!"}}, nil)

	// OTP users are sent back to sign in with a fresh code (ubccr#127)
	resp := tc.postForm("/auth/expiredpw", url.Values{
		"password":     {"OldSecret123!"},
		"newpassword":  {"NewSecret456!"},
		"newpassword2": {"NewSecret456!"},
		"otp":          {"123456"},
	}, nil)
	assert.Equal("/auth/login", resp.Header.Get("HX-Redirect"))

	resp = tc.postForm("/auth/authenticate", url.Values{"username": {"walter"}, "password": {"NewSecret456!"}}, nil)
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	assert.Equal(faContinueTarget, resp.Header.Get("HX-Redirect"))
}
