package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

// recordingCaptchaStore remembers captcha digits so tests can "solve" them
type recordingCaptchaStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *recordingCaptchaStore) Set(id string, digits []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = append([]byte(nil), digits...)
}

func (s *recordingCaptchaStore) Get(id string, clear bool) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.m[id]
	if clear {
		delete(s.m, id)
	}
	return d
}

var (
	captchaStore     = &recordingCaptchaStore{m: make(map[string][]byte)}
	captchaStoreOnce sync.Once
)

// captchaSolution returns the answer for a captcha id generated after
// newTestApp installed the recording store
func captchaSolution(t *testing.T, id string) string {
	t.Helper()
	captchaStore.mu.Lock()
	defer captchaStore.mu.Unlock()
	digits, ok := captchaStore.m[id]
	if !ok {
		t.Fatalf("no captcha recorded for id %s", id)
	}
	sol := make([]byte, len(digits))
	for i, d := range digits {
		sol[i] = '0' + d
	}
	return string(sol)
}

// newTestApp builds the real fiber app (routes, middleware, CSRF, sessions)
// wired to a fake FreeIPA server. Tests share package-global viper config, so
// they cannot run in parallel — same constraint the existing tests have.
func newTestApp(t *testing.T) (*fiber.App, *Router, *fakeIPA) {
	t.Helper()
	return newTestAppWith(t, nil)
}

// newTestAppWith applies extra viper config (routes depend on some settings
// at build time) before assembling the app
func newTestAppWith(t *testing.T, configure func()) (*fiber.App, *Router, *fakeIPA) {
	t.Helper()

	fake := newFakeIPA()
	t.Cleanup(fake.Close)

	captchaStoreOnce.Do(func() { captcha.SetCustomStore(captchaStore) })

	viper.Reset()
	SetDefaults()
	viper.Set("storage.driver", "memory")
	viper.Set("server.secure_cookies", false)
	viper.Set("server.rate_limit_max", 10000)
	viper.Set("server.csrf_secret", "test-csrf-secret")
	// 32-byte hex key for branca email tokens
	viper.Set("email.token_secret", strings.Repeat("ab", 32))
	viper.Set("email.smtp_host", "127.0.0.1")
	viper.Set("email.smtp_port", 1) // nothing listens; sends fail fast, handlers log and continue

	if configure != nil {
		configure()
	}

	origNew := newIPAClient
	origNewWithSession := newIPAClientWithSession
	origKeytabLogin := ipaKeytabLogin
	origRPCClient := ipaRPCHTTPClient
	t.Cleanup(func() {
		newIPAClient = origNew
		newIPAClientWithSession = origNewWithSession
		ipaKeytabLogin = origKeytabLogin
		ipaRPCHTTPClient = origRPCClient
	})
	ipaRPCHTTPClient = fake.srv.Client()

	newIPAClient = fake.client
	newIPAClientWithSession = func(sid string) *ipa.Client {
		c := fake.client()
		c.RemoteLogin("__restore__", sid)
		return c
	}
	ipaKeytabLogin = func(c *ipa.Client, keytab, username string) error {
		return c.RemoteLogin("__admin__", "")
	}

	app, router, err := newFiber()
	if err != nil {
		t.Fatalf("failed to build app: %s", err)
	}
	// Handlers fire notification emails from tracked background
	// goroutines (Router.goBG); wait for them here so they can't still be
	// reading global viper config when the next test resets it.
	t.Cleanup(router.bg.Wait)

	return app, router, fake
}

var csrfPattern = regexp.MustCompile(`X-CSRF-Token": "([^"]+)"`)

// testClient drives the fiber app via app.Test with a cookie jar, mimicking a
// browser + htmx
type testClient struct {
	t       *testing.T
	app     *fiber.App
	cookies map[string]string
	csrf    string
}

func newTestClient(t *testing.T, app *fiber.App) *testClient {
	return &testClient{t: t, app: app, cookies: make(map[string]string)}
}

func (tc *testClient) do(req *http.Request) *http.Response {
	tc.t.Helper()

	for name, value := range tc.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	resp, err := tc.app.Test(req, 10000)
	if err != nil {
		tc.t.Fatalf("request %s %s failed: %s", req.Method, req.URL.Path, err)
	}

	for _, c := range resp.Cookies() {
		if c.Value == "" || c.MaxAge < 0 {
			delete(tc.cookies, c.Name)
			continue
		}
		tc.cookies[c.Name] = c.Value
	}

	return resp
}

func (tc *testClient) get(path string, headers ...map[string]string) *http.Response {
	req := httptest.NewRequest("GET", path, nil)
	for _, h := range headers {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	return tc.do(req)
}

// getCSRF fetches a page and captures the CSRF token embedded in the HTML
func (tc *testClient) getCSRF(path string) {
	tc.t.Helper()
	resp := tc.get(path)
	body := readBody(tc.t, resp)
	m := csrfPattern.FindStringSubmatch(body)
	if m == nil {
		tc.t.Fatalf("no CSRF token found in %s (status %d)", path, resp.StatusCode)
	}
	tc.csrf = m[1]
}

func (tc *testClient) postForm(path string, form url.Values, headers map[string]string) *http.Response {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if tc.csrf != "" {
		req.Header.Set("X-CSRF-Token", tc.csrf)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return tc.do(req)
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %s", err)
	}
	resp.Body.Close()
	return string(b)
}

// login performs the full two-step login flow and asserts success
func (tc *testClient) login(username, password string) {
	tc.t.Helper()
	tc.getCSRF("/auth/login")

	resp := tc.postForm("/auth/authenticate", url.Values{
		"username": {username},
		"password": {password},
	}, nil)
	if resp.StatusCode != fiber.StatusNoContent {
		tc.t.Fatalf("login for %s: expected 204, got %d: %s", username, resp.StatusCode, readBody(tc.t, resp))
	}
}
