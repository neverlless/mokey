//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Account lifecycle against the real FreeIPA: manager and
// krbPrincipalExpiration written by mokey's service account through the
// permission from docs/install.md, which setupStand grants. test/compose.yml
// sets renewal_period = 365d and max_changes_per_run = 1.

var expRe = regexp.MustCompile(`(?m)^\s*krbprincipalexpiration: (\d{14}Z)$`)

const ipaTime = "20060102150405Z"

// expiry returns the account's raw krbPrincipalExpiration, "" when unset
func expiry(t *testing.T, uid string) string {
	t.Helper()
	if m := expRe.FindStringSubmatch(userRaw(t, uid)); m != nil {
		return m[1]
	}
	return ""
}

// day returns midnight UTC n days from today, as FreeIPA writes it
func day(n int) string {
	return time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, n).Format(ipaTime)
}

func setExpiryCLI(t *testing.T, uid, at string) {
	t.Helper()
	mustIPA(t, "user-mod", uid, "--principal-expiration="+at)
}

func adminDo(t *testing.T, admin *client, action string, form url.Values) {
	t.Helper()
	if code, body := admin.hx("/admin/user/"+action, form); code != http.StatusOK {
		t.Fatalf("admin %s %v: %d %s", action, form, code, body)
	}
}

func extend(t *testing.T, sponsor *client, uid string) {
	t.Helper()
	if code, body := sponsor.hx("/groups/sponsored/extend", url.Values{"username": {uid}}); code != http.StatusOK {
		t.Fatalf("extend %s: %d %s", uid, code, body)
	}
}

// The sponsor set by an admin in mokey is FreeIPA's manager; the sponsor's
// Extend is capped by the sponsor's own date; the user reads both on Profile
// through their own FreeIPA session.
func TestLifecycleSponsorExtendCapped(t *testing.T) {
	stand(t)
	sponsor, member := newUser(t), newUser(t)
	own := day(100)
	setExpiryCLI(t, sponsor.uid, own)

	admin := login(t, "admin", ipaAdminPw)
	adminDo(t, admin, "set-sponsor", url.Values{"username": {member.uid}, "sponsor": {sponsor.uid}})
	if out := mustIPA(t, "user-show", member.uid, "--all"); !strings.Contains(out, "Manager: "+sponsor.uid) {
		t.Fatalf("manager not set in FreeIPA:\n%s", out)
	}
	adminDo(t, admin, "set-expiry", url.Values{"username": {member.uid}, "expires": {time.Now().AddDate(0, 0, 10).Format("2006-01-02")}})
	if expiry(t, member.uid) == "" {
		t.Fatal("admin set-expiry left krbPrincipalExpiration empty")
	}

	sc := login(t, sponsor.uid, sponsor.password)
	if _, body := sc.get("/groups"); !strings.Contains(body, `"username": "`+member.uid+`"`) {
		t.Fatalf("%s is not under People you sponsor:\n%s", member.uid, body)
	}
	extend(t, sc, member.uid)
	if got := expiry(t, member.uid); got != own {
		t.Fatalf("extend: want the sponsor's date %s, got %q", own, got)
	}

	mc := login(t, member.uid, member.password)
	_, body := mc.get("/account")
	if !strings.Contains(body, `id="account-expires"`) || !strings.Contains(body, "Account valid until") {
		t.Fatalf("Profile does not show the account expiry:\n%s", body)
	}
	if !strings.Contains(body, `id="account-sponsor"`) || !strings.Contains(body, sponsor.uid) {
		t.Errorf("Profile does not show the sponsor %s", sponsor.uid)
	}
}

// After the date Kerberos refuses the account; the sponsor's Extend restores
// it for renewal_period.
func TestLifecycleExpiredAccountSignIn(t *testing.T) {
	stand(t)
	sponsor, member := newUser(t), newUser(t)
	mustIPA(t, "user-mod", member.uid, "--manager="+sponsor.uid)

	admin := login(t, "admin", ipaAdminPw)
	adminDo(t, admin, "set-expiry", url.Values{"username": {member.uid}, "expires": {time.Now().AddDate(0, 0, -1).Format("2006-01-02")}})
	if code := newClient(t).tryLogin(member.uid, member.password, ""); code == http.StatusNoContent {
		t.Fatal("expired account signed in to mokey")
	}

	extend(t, login(t, sponsor.uid, sponsor.password), member.uid)
	got := expiry(t, member.uid)
	// now + 365d: today's or, around midnight UTC, tomorrow's date
	if d0, d1 := day(365)[:8], day(366)[:8]; got == "" || (got[:8] != d0 && got[:8] != d1) {
		t.Fatalf("extend: want %s or %s, got %q", d0, d1, got)
	}
	if code := newClient(t).tryLogin(member.uid, member.password, ""); code != http.StatusNoContent {
		t.Fatalf("extended account: want 204, got %d", code)
	}
}

// Two accounts ending after their sponsor: a plan over max_changes_per_run
// that the admin's Apply writes in full.
func TestLifecycleAdminApplyPastBrake(t *testing.T) {
	stand(t)
	sponsor, a, b := newUser(t), newUser(t), newUser(t)
	own := day(60)
	setExpiryCLI(t, sponsor.uid, own)
	for _, u := range []*testUser{a, b} {
		mustIPA(t, "user-mod", u.uid, "--manager="+sponsor.uid, "--principal-expiration="+day(200))
	}

	admin := login(t, "admin", ipaAdminPw)
	if code, body := admin.hx("/admin/lifecycle/apply", nil); code != http.StatusOK {
		t.Fatalf("apply: %d %s", code, body)
	}
	// Apply runs in the background; the status fragment shows its outcome
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, body := admin.do("GET", "/admin/lifecycle/status", nil, true)
		if strings.Contains(body, "changes applied") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("apply did not finish: %s", body)
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, u := range []*testUser{a, b} {
		if got := expiry(t, u.uid); got != own {
			t.Errorf("%s: want the sponsor's date %s, got %q", u.uid, own, got)
		}
	}
}
