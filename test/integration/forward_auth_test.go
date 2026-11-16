//go:build integration

package integration

import (
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var hopRe = regexp.MustCompile(`<meta http-equiv="refresh" content="0;url=([^"]+)">`)

// faOpen opens u as a browser would: following redirects and mokey's
// meta-refresh hop. It returns the final status, URL and body.
func (c *client) faOpen(u string) (int, string, string) {
	c.t.Helper()
	for range 10 {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			c.t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html")
		resp, err := c.http.Do(req)
		if err != nil {
			c.t.Fatalf("GET %s: %s", u, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(b)
		next := resp.Header.Get("Location")
		if resp.StatusCode/100 != 3 {
			next = ""
			if m := hopRe.FindStringSubmatch(body); m != nil {
				next = html.UnescapeString(m[1])
			}
		}
		if next == "" {
			return resp.StatusCode, u, body
		}
		nu, err := resp.Request.URL.Parse(next)
		if err != nil {
			c.t.Fatalf("redirect from %s to %q: %s", u, next, err)
		}
		u = nu.String()
	}
	c.t.Fatalf("too many redirects, last %s", u)
	return 0, "", ""
}

// faStep makes one browser request without following redirects
func (c *client) faStep(u string) (int, string) {
	c.t.Helper()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Accept", "text/html")
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("GET %s: %s", u, err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func TestForwardAuthRedirectsToMokey(t *testing.T) {
	faStand(t)
	c := newProxyClient(t)

	code, loc := c.faStep(faAppURL + "/report?x=1")
	if code != http.StatusFound || !strings.HasPrefix(loc, faAppURL+"/.mokey/start?") {
		t.Fatalf("app without a session: want 302 to /.mokey/start, got %d %q", code, loc)
	}
	code, loc = c.faStep(loc)
	if code != http.StatusFound || !strings.HasPrefix(loc, faIDURL+"/forward-auth/continue?") {
		t.Fatalf("/.mokey/start: want 302 to mokey, got %d %q", code, loc)
	}
	code, u, body := c.faOpen(loc)
	if code != http.StatusOK || !strings.HasPrefix(u, faIDURL+"/auth/login") || !strings.Contains(body, `id="username"`) {
		t.Fatalf("signed out: want mokey's login form, got %d at %s", code, u)
	}
}

func TestForwardAuthInGroup(t *testing.T) {
	faStand(t)
	u := newUser(t)
	mustIPA(t, "group-add-member", faGroup, "--users="+u.uid)
	c := newProxyClient(t)
	c.login(u.uid, u.password)

	code, at, body := c.faOpen(faAppURL + "/report?x=1")
	if code != http.StatusOK || at != faAppURL+"/report?x=1" {
		t.Fatalf("want whoami at the requested URL, got %d at %s:\n%s", code, at, body)
	}
	for _, want := range []string{"GET /report?x=1", "X-Auth-Request-User: " + u.uid, "X-Auth-Request-Email: " + u.email, faGroup} {
		if !strings.Contains(body, want) {
			t.Errorf("whoami response lacks %q:\n%s", want, body)
		}
	}
	// the app session now stands on its own
	if code, _ := c.faStep(faAppURL + "/"); code != http.StatusOK {
		t.Fatalf("second request: want 200, got %d", code)
	}
}

func TestForwardAuthNotInGroup(t *testing.T) {
	faStand(t)
	u := newUser(t)
	c := newProxyClient(t)
	c.login(u.uid, u.password)

	code, at, body := c.faOpen(faAppURL + "/")
	if code != http.StatusForbidden || !strings.HasPrefix(at, faIDURL+"/forward-auth/continue?") || !strings.Contains(body, faGroup) {
		t.Fatalf("not in %s: want 403 naming the group, got %d at %s:\n%s", faGroup, code, at, body)
	}
	if code, loc := c.faStep(faAppURL + "/"); code != http.StatusFound || !strings.HasPrefix(loc, faAppURL+"/.mokey/start?") {
		t.Fatalf("denied user got an app session: %d %q", code, loc)
	}
}
