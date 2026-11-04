//go:build integration || e2e

// Package integration drives a running mokey and its real FreeIPA (the demo
// stand in examples/demo) over HTTP and through a browser. See test/README.md.
package integration

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	baseURL     = strings.TrimRight(os.Getenv("MOKEY_IT_URL"), "/")
	mailpitURL  = envOr("MOKEY_IT_MAILPIT_URL", "http://localhost:8025")
	ipaCtr      = envOr("MOKEY_IT_IPA_CONTAINER", "demo-ipa-1")
	ipaAdminPw  = os.Getenv("MOKEY_IT_IPA_ADMIN_PASSWORD")
	runID       = randHex(3)
	policyGroup = "it" + runID
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func TestMain(m *testing.M) {
	if baseURL == "" {
		fmt.Println("MOKEY_IT_URL is not set; skipping tests against a live stand")
		os.Exit(m.Run())
	}
	if ipaAdminPw == "" {
		ipaAdminPw = demoAdminSecret()
	}
	if err := setupStand(); err != nil {
		fmt.Fprintln(os.Stderr, "stand setup:", err)
		os.Exit(1)
	}
	code := m.Run()
	_, _ = ipaCmd("", "pwpolicy-del", policyGroup)
	_, _ = ipaCmd("", "group-del", policyGroup)
	os.Exit(code)
}

// demoAdminSecret reads the admin password from the demo compose file, so it
// lives in exactly one place
func demoAdminSecret() string {
	b, err := os.ReadFile("../../examples/demo/compose.yml")
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`x-admin-password: &admin-password "([^"]+)"`).FindSubmatch(b)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// setupStand creates a per-run group whose password policy every test user
// joins: a stricter policy than the global one to test against, and no
// minimum lifetime so a user may change their password twice in a run
func setupStand() error {
	if out, err := runDocker(ipaAdminPw+"\n", "exec", "-i", "-e", "KRB5CCNAME=FILE:/tmp/krb5cc_it", ipaCtr, "kinit", "admin"); err != nil {
		return fmt.Errorf("kinit admin in %s: %w: %s", ipaCtr, err, out)
	}
	if out, err := ipaCmd("", "group-add", policyGroup, "--desc=mokey integration run "+runID); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	prio := fmt.Sprint(100 + time.Now().UnixNano()%9000)
	if out, err := ipaCmd("", "pwpolicy-add", policyGroup, "--priority="+prio, "--minlife=0", "--minlength=12", "--minclasses=3"); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func runDocker(stdin string, args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ipaCmd runs the ipa CLI as admin inside the FreeIPA container
func ipaCmd(stdin string, args ...string) (string, error) {
	return runDocker(stdin, append([]string{"exec", "-i", "-e", "KRB5CCNAME=FILE:/tmp/krb5cc_it", ipaCtr, "ipa"}, args...)...)
}

func mustIPA(t *testing.T, args ...string) string {
	t.Helper()
	out, err := ipaCmd("", args...)
	if err != nil {
		t.Fatalf("ipa %s: %s: %s", strings.Join(args, " "), err, out)
	}
	return out
}

func userRaw(t *testing.T, uid string) string {
	t.Helper()
	return mustIPA(t, "user-show", uid, "--all", "--raw")
}

func stand(t *testing.T) {
	t.Helper()
	if baseURL == "" {
		t.Skip("MOKEY_IT_URL is not set")
	}
}

// newPassword returns a fresh password that satisfies the run's policy
func newPassword() string { return "It-" + randHex(6) + "-Aa1" }

type testUser struct {
	uid, email, password string
}

// newUser creates an active FreeIPA user under the run's password policy and
// deletes it when the test ends
func newUser(t *testing.T) *testUser {
	t.Helper()
	u := &testUser{uid: "it" + randHex(4), password: newPassword()}
	u.email = u.uid + "@mokey.test"
	if out, err := ipaCmd(u.password+"\n", "user-add", u.uid, "--first=It", "--last=User", "--email="+u.email, "--password"); err != nil {
		t.Fatalf("user-add: %s: %s", err, out)
	}
	cleanupUser(t, u.uid)
	// An admin-set password is born expired; skip the forced change
	mustIPA(t, "user-mod", u.uid, "--setattr=krbPasswordExpiration=20380101000000Z")
	joinPolicy(t, u.uid)
	return u
}

func joinPolicy(t *testing.T, uid string) {
	t.Helper()
	mustIPA(t, "group-add-member", policyGroup, "--users="+uid)
}

func cleanupUser(t *testing.T, uid string) {
	t.Cleanup(func() {
		_, _ = ipaCmd("", "user-del", uid)
		_, _ = ipaCmd("", "stageuser-del", uid)
	})
}

// client is a cookie-keeping HTTP client that speaks to mokey like the
// browser + htmx do, CSRF token included
type client struct {
	t    *testing.T
	http *http.Client
	csrf string
}

var csrfRe = regexp.MustCompile(`X-CSRF-Token": "([^"]+)"`)

func newClient(t *testing.T) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, http: &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

func (c *client) do(method, path string, form url.Values, htmx bool) (int, string) {
	c.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %s", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	s := string(b)
	if m := csrfRe.FindStringSubmatch(s); m != nil {
		c.csrf = m[1]
	}
	return resp.StatusCode, s
}

func (c *client) get(path string) (int, string) { return c.do("GET", path, nil, false) }

func (c *client) post(path string, form url.Values) (int, string) {
	return c.do("POST", path, form, false)
}

func (c *client) hx(path string, form url.Values) (int, string) {
	c.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	return c.do("POST", path, form, true)
}

// tryLogin runs mokey's two-step login and returns the status code of the
// step that stopped it
func (c *client) tryLogin(uid, password, otp string) int {
	c.t.Helper()
	c.get("/auth/login")
	if code, _ := c.post("/auth/login", url.Values{"username": {uid}}); code != http.StatusOK {
		return code
	}
	code, _ := c.post("/auth/authenticate", url.Values{"username": {uid}, "password": {password}, "otp": {otp}})
	return code
}

func login(t *testing.T, uid, password string) *client {
	t.Helper()
	c := newClient(t)
	if code := c.tryLogin(uid, password, ""); code != http.StatusNoContent {
		t.Fatalf("login %s: want 204, got %d", uid, code)
	}
	// pick up the CSRF token of the logged-in session
	if code, _ := c.get("/"); code != http.StatusOK {
		t.Fatalf("index after login: %d", code)
	}
	return c
}

// mailLink waits for a message to addr in Mailpit and returns the path of the
// first link matching pathPrefix
func mailLink(t *testing.T, addr, pathPrefix string) string {
	t.Helper()
	re := regexp.MustCompile(regexp.QuoteMeta(pathPrefix) + `[A-Za-z0-9_\-.~]+`)
	q := url.Values{"query": {`to:"` + addr + `"`}}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var list struct {
			Messages []struct{ ID string }
		}
		getJSON(t, mailpitURL+"/api/v1/search?"+q.Encode(), &list)
		for _, m := range list.Messages {
			var msg struct{ Text, HTML string }
			getJSON(t, mailpitURL+"/api/v1/message/"+m.ID, &msg)
			if l := re.FindString(html.UnescapeString(msg.Text + msg.HTML)); l != "" {
				return l
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("no mail to %s with a %s link", addr, pathPrefix)
	return ""
}

func getJSON(t *testing.T, u string, v any) {
	t.Helper()
	resp, err := http.Get(u) // #nosec G107 -- local Mailpit URL from the test environment
	if err != nil {
		t.Fatalf("GET %s: %s", u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(v); err != nil {
		t.Fatalf("GET %s: %s: %s", u, err, b)
	}
}
