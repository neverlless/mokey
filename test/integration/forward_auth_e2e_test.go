//go:build e2e

package integration

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mxschmitt/playwright-go"
)

// Signed in to mokey first, the app opens without a second login form,
// although mokey's session cookie is SameSite=Strict and the sign-in hop
// arrives from the app's site. Signing out of mokey ends the app session.
func TestForwardAuthBrowserSignIn(t *testing.T) {
	faStand(t)
	u := newUser(t)
	mustIPA(t, "group-add-member", faGroup, "--users="+u.uid)
	_, page := newProxyPage(t)
	browserLoginAt(t, page, faIDURL, u)

	var mu sync.Mutex
	var logins []string
	page.OnRequest(func(r playwright.Request) {
		if strings.Contains(r.URL(), "/auth/login") {
			mu.Lock()
			logins = append(logins, r.URL())
			mu.Unlock()
		}
	})
	_, err := page.Goto(faAppURL + "/report?x=1")
	must(t, err)
	must(t, page.WaitForURL(faAppURL+"/report?x=1"))
	body, err := page.Locator("body").InnerText()
	must(t, err)
	if !strings.Contains(body, "X-Auth-Request-User: "+u.uid) {
		t.Fatalf("whoami lacks the user header:\n%s", body)
	}
	mu.Lock()
	if len(logins) > 0 {
		t.Fatalf("signed-in user was sent to the login form: %v", logins)
	}
	mu.Unlock()

	_, err = page.Goto(faIDURL + "/")
	must(t, err)
	must(t, page.Locator("#logout").Click())
	must(t, page.WaitForURL(faIDURL+"/auth/login**"))

	_, err = page.Goto(faAppURL + "/report?x=1")
	must(t, err)
	must(t, page.WaitForURL(faIDURL+"/auth/login**"))
	must(t, page.Locator("#username").WaitFor())
}

// A member removed from the app's group gets mokey's denied page on the
// app's host at the next recheck, styled by mokey's stylesheets loaded
// cross-origin (SRI + CORS) from id.mokey.test.
func TestForwardAuthBrowserDeniedStyled(t *testing.T) {
	faStand(t)
	u := newUser(t)
	mustIPA(t, "group-add-member", faGroup, "--users="+u.uid)
	_, page := newProxyPage(t)
	browserLoginAt(t, page, faIDURL, u)
	_, err := page.Goto(faAppURL + "/")
	must(t, err)
	must(t, page.WaitForURL(faAppURL+"/"))

	mustIPA(t, "group-remove-member", faGroup, "--users="+u.uid)
	// access ends at the next recheck (forward_auth.recheck in test/forward-auth/mokey.toml)
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := page.Goto(faAppURL + "/")
		must(t, err)
		if resp.Status() == 403 && page.URL() == faAppURL+"/" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("removed member: want 403 on the app host, got %d at %s", resp.Status(), page.URL())
		}
		time.Sleep(time.Second)
	}
	body, err := page.Locator("body").InnerText()
	must(t, err)
	if !strings.Contains(body, faGroup) {
		t.Errorf("denied page does not name %s:\n%s", faGroup, body)
	}
	// cssRules of a cross-origin sheet is readable only if it loaded with CORS
	rules, err := page.Evaluate(`() => [...document.styleSheets]
		.filter(s => s.href && s.href.startsWith("` + faIDURL + `/static/css/style.css"))
		.map(s => s.cssRules.length)`)
	must(t, err)
	if r, _ := rules.([]any); len(r) != 1 || fmt.Sprint(r[0]) == "0" {
		t.Fatalf("mokey's stylesheet did not load on the app host: %v", rules)
	}
}
