//go:build e2e

package integration

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/mxschmitt/playwright-go"
)

// newPage starts Chromium and fails the test on any console error or
// uncaught exception the page reports
func newPage(t *testing.T) (playwright.BrowserContext, playwright.Page) {
	t.Helper()
	pw, err := playwright.Run()
	if err != nil {
		t.Fatalf("playwright: %s (install the driver: see test/README.md)", err)
	}
	t.Cleanup(func() { _ = pw.Stop() })
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{Headless: playwright.Bool(os.Getenv("MOKEY_E2E_HEADED") == "")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := browser.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	page.SetDefaultTimeout(15000)
	page.OnConsole(func(m playwright.ConsoleMessage) {
		if m.Type() == "error" {
			t.Errorf("console error on %s: %s", page.URL(), m.Text())
		}
	})
	page.OnPageError(func(err error) { t.Errorf("page error on %s: %s", page.URL(), err) })
	page.OnDialog(func(d playwright.Dialog) { _ = d.Accept() })
	return ctx, page
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func browserLogin(t *testing.T, page playwright.Page, u *testUser) {
	t.Helper()
	_, err := page.Goto(baseURL + "/auth/login")
	must(t, err)
	must(t, page.Locator("#username").Fill(u.uid))
	must(t, page.Locator("#username").Press("Enter"))
	must(t, page.Locator("#password").Fill(u.password))
	must(t, page.Locator("#password").Press("Enter"))
	must(t, page.WaitForURL(baseURL+"/"))
}

func TestBrowserSmoke(t *testing.T) {
	stand(t)
	u := newUser(t)
	_, page := newPage(t)
	browserLogin(t, page, u)

	for _, p := range []string{"/", "/account", "/password", "/security", "/sshkey", "/otp", "/passkey", "/groups", "/access"} {
		resp, err := page.Goto(baseURL + p)
		must(t, err)
		if resp.Status() != 200 {
			t.Errorf("%s: %d", p, resp.Status())
		}
		// tabs load their content with htmx after the page itself
		must(t, page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{State: playwright.LoadStateNetworkidle}))
	}
}

func TestPasskeyEnrollment(t *testing.T) {
	stand(t)
	if !strings.HasPrefix(baseURL, "http://localhost") && !strings.HasPrefix(baseURL, "https://") {
		t.Skip("passkeys need a secure context: use http://localhost")
	}
	u := newUser(t)
	ctx, page := newPage(t)

	cdp, err := ctx.NewCDPSession(page)
	must(t, err)
	_, err = cdp.Send("WebAuthn.enable", map[string]any{"enableUI": false})
	must(t, err)
	res, err := cdp.Send("WebAuthn.addVirtualAuthenticator", map[string]any{"options": map[string]any{
		"protocol":                    "ctap2",
		"transport":                   "internal",
		"hasResidentKey":              true,
		"hasUserVerification":         true,
		"isUserVerified":              true,
		"automaticPresenceSimulation": true,
	}})
	must(t, err)
	authID := res.(map[string]any)["authenticatorId"]

	browserLogin(t, page, u)
	_, err = page.Goto(baseURL + "/passkey")
	must(t, err)
	must(t, page.Locator("#passkey-register").Click())
	// the page reloads with the new passkey listed
	entry := page.Locator("#passkey .mokey-mono")
	must(t, entry.WaitFor())

	creds, err := cdp.Send("WebAuthn.getCredentials", map[string]any{"authenticatorId": authID})
	must(t, err)
	if n := len(creds.(map[string]any)["credentials"].([]any)); n != 1 {
		t.Fatalf("authenticator holds %d credentials, want 1", n)
	}

	m := regexp.MustCompile(`ipapasskey: passkey:([^,\s]+)`).FindStringSubmatch(userRaw(t, u.uid))
	if m == nil {
		t.Fatal("no passkey on the user in FreeIPA")
	}
	shortID, err := entry.TextContent()
	must(t, err)
	if !strings.HasPrefix(m[1], strings.TrimSuffix(shortID, "…")) {
		t.Fatalf("listed passkey %q is not FreeIPA's %q", shortID, m[1])
	}

	must(t, page.Locator("#passkey button.btn-outline-danger").Click())
	must(t, entry.WaitFor(playwright.LocatorWaitForOptions{State: playwright.WaitForSelectorStateDetached}))
	if strings.Contains(userRaw(t, u.uid), "ipapasskey: passkey:") {
		t.Fatal("passkey still in FreeIPA after delete")
	}
}
