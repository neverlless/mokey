package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/neverlless/goipa/ipatest"
	"github.com/stretchr/testify/assert"
)

// go-webauthn v0.18 rejects a relying party id that is an IP address or a bare
// single label (its MIGRATION.md §2.1), and mokey derives that id from the
// request host. Reaching the portal that way used to answer "fatal system
// error", which tells the operator nothing about what to change.
func TestPasskeyRejectsUnusableHostname(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	begin := func(host string) *http.Response {
		tc := newTestClient(t, app)
		tc.login("walter", "Secret123!")
		tc.getCSRF("/passkey")

		req := httptest.NewRequest("POST", "/passkey/begin", strings.NewReader(url.Values{}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", tc.csrf)
		req.Host = host
		return tc.do(req)
	}

	for _, host := range []string{"10.0.0.5", "10.0.0.5:8080", "mokey"} {
		resp := begin(host)
		assert.Equal(fiber.StatusBadRequest, resp.StatusCode, "host %q", host)
		assert.Equal(T("passkey.bad_hostname"), readBody(t, resp), "host %q", host)
	}

	// a fully qualified name is fine, and so is localhost for development
	for _, host := range []string{"idm.example.com", "localhost", "localhost:8080"} {
		resp := begin(host)
		assert.NotEqual(fiber.StatusBadRequest, resp.StatusCode, "host %q", host)
	}
}

// failingSetStorage accepts reads but cannot persist writes
type failingSetStorage struct{ fiber.Storage }

func (s *failingSetStorage) Set(key string, val []byte, exp time.Duration) error {
	return errors.New("storage backend down")
}

// The registration challenge is single use: PasskeyFinish removes it from the
// session before verifying. If that removal cannot be saved, the challenge
// stays valid in storage, so the request must stop instead of carrying on.
func TestPasskeyFinishStopsWhenChallengeNotConsumed(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	tc.getCSRF("/passkey")

	post := func(path string) *http.Response {
		req := httptest.NewRequest("POST", path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", tc.csrf)
		req.Host = "idm.example.com"
		return tc.do(req)
	}

	resp := post("/passkey/begin")
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	router.sessionStore = session.New(session.Config{
		Storage: &failingSetStorage{router.storage},
	})

	resp = post("/passkey/finish")
	assert.Equal(fiber.StatusInternalServerError, resp.StatusCode)
	assert.Equal(T("account.fatal_system_error"), readBody(t, resp))
}
