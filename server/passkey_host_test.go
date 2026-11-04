package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
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

	// FreeIPA hosts accept passkeys only for the IPA domain (test.local here),
	// so the portal registers them for it; localhost stays open for development
	for host, rpID := range map[string]string{
		"idm.test.local": "test.local", "TEST.local:8443": "test.local",
		"localhost": "localhost", "localhost:8080": "localhost",
	} {
		resp := begin(host)
		if assert.Equal(fiber.StatusOK, resp.StatusCode, "host %q", host) {
			assert.Contains(readBody(t, resp), `"id":"`+rpID+`"`, "host %q", host)
		}
	}

	// a credential for any other id would fail on the hosts
	resp := begin("idm.example.com")
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	assert.Contains(readBody(t, resp), "test.local")
}

// failingSetStorage accepts reads but cannot persist writes
type failingSetStorage struct{ fiber.Storage }

func (s *failingSetStorage) Set(key string, val []byte, exp time.Duration) error {
	return errors.New("storage backend down")
}

func (s *failingSetStorage) SetWithContext(_ context.Context, key string, val []byte, exp time.Duration) error {
	return s.Set(key, val, exp)
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
		req.Host = "idm.test.local"
		return tc.do(req)
	}

	resp := post("/passkey/begin")
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	router.sessionStore = session.NewStore(session.Config{
		Storage: &failingSetStorage{router.storage},
	})

	resp = post("/passkey/finish")
	assert.Equal(fiber.StatusInternalServerError, resp.StatusCode)
	assert.Equal(T("account.fatal_system_error"), readBody(t, resp))
}
