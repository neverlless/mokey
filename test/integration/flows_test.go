//go:build integration

package integration

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestLogin(t *testing.T) {
	stand(t)
	u := newUser(t)

	if code := newClient(t).tryLogin(u.uid, u.password+"x", ""); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: want 401, got %d", code)
	}
	c := login(t, u.uid, u.password)
	if code, body := c.get("/account"); code != http.StatusOK || !strings.Contains(body, u.uid) {
		t.Fatalf("account page: %d", code)
	}
}

func TestPasswordChangePolicy(t *testing.T) {
	stand(t)
	u := newUser(t)
	c := login(t, u.uid, u.password)

	// 11 characters, three classes: below the run policy's minimum of 12
	short := "Ab1" + randHex(4)
	c.hx("/password/change", url.Values{"password": {u.password}, "newpassword": {short}, "newpassword2": {short}})
	if code := newClient(t).tryLogin(u.uid, short, ""); code == http.StatusNoContent {
		t.Fatal("a password shorter than the FreeIPA policy was accepted")
	}

	next := newPassword()
	if code, _ := c.hx("/password/change", url.Values{"password": {u.password}, "newpassword": {next}, "newpassword2": {next}}); code != http.StatusOK {
		t.Fatalf("password change: %d", code)
	}
	if code := newClient(t).tryLogin(u.uid, u.password, ""); code != http.StatusUnauthorized {
		t.Fatalf("old password: want 401, got %d", code)
	}
	login(t, u.uid, next)
}

func TestForgotPassword(t *testing.T) {
	stand(t)
	u := newUser(t)
	c := newClient(t)
	if _, body := c.get("/auth/forgotpw"); strings.Contains(body, "captcha_id") {
		t.Skip("CAPTCHA is on; start mokey with test/compose.yml")
	}
	if code, body := c.post("/auth/forgotpw", url.Values{"username": {u.uid}}); code != http.StatusOK {
		t.Fatalf("forgot password: %d %s", code, body)
	}

	link := mailLink(t, u.email, "/auth/resetpw/")
	r := newClient(t)
	if code, _ := r.get(link); code != http.StatusOK {
		t.Fatalf("reset page: %d", code)
	}
	next := newPassword()
	if code, body := r.post(link, url.Values{"password": {next}, "password2": {next}}); code != http.StatusOK {
		t.Fatalf("reset: %d %s", code, body)
	}
	login(t, u.uid, next)
	if code, _ := newClient(t).get(link); code != http.StatusNotFound {
		t.Fatalf("reset link reused: want 404, got %d", code)
	}
}

func TestSignup(t *testing.T) {
	stand(t)
	c := newClient(t)
	code, body := c.get("/signup")
	if code == http.StatusNotFound {
		t.Skip("signup is disabled")
	}
	if strings.Contains(body, "captcha_id") {
		t.Skip("CAPTCHA is on; start mokey with test/compose.yml")
	}

	uid := "it" + randHex(4)
	cleanupUser(t, uid)
	email := uid + "@mokey.test"
	pw := newPassword()
	if code, body := c.post("/signup", url.Values{
		"username": {uid}, "email": {email}, "first": {"It"}, "last": {"Signup"},
		"password": {pw}, "password2": {pw},
	}); code != http.StatusOK {
		t.Fatalf("signup: %d %s", code, body)
	}
	if code := newClient(t).tryLogin(uid, pw, ""); code == http.StatusNoContent {
		t.Fatal("logged in before verifying the email")
	}

	link := mailLink(t, email, "/auth/verify/")
	v := newClient(t)
	v.get(link)
	if code, body := v.post(link, url.Values{}); code != http.StatusOK {
		t.Fatalf("verify: %d %s", code, body)
	}
	login(t, uid, pw)
}

const sshKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH+UB4lYzT8fJo/4GSbomgNYqQ3Z9qIsLGwKyjjfdtX4 mokey-it"

var fpRe = regexp.MustCompile(`"fp": "([^"]+)"`)

func TestSSHKey(t *testing.T) {
	stand(t)
	u := newUser(t)
	c := login(t, u.uid, u.password)

	code, body := c.hx("/sshkey/add", url.Values{"title": {"it laptop"}, "key": {sshKey}})
	if code != http.StatusOK {
		t.Fatalf("add key: %d %s", code, body)
	}
	if !strings.Contains(userRaw(t, u.uid), "it laptop (ssh-ed25519)") {
		t.Fatal("key not stored in FreeIPA")
	}
	m := fpRe.FindStringSubmatch(html.UnescapeString(body))
	if m == nil {
		t.Fatalf("no fingerprint in the key list: %s", body)
	}
	if code, body := c.hx("/sshkey/remove", url.Values{"fp": {m[1]}}); code != http.StatusOK {
		t.Fatalf("remove key: %d %s", code, body)
	}
	if strings.Contains(userRaw(t, u.uid), "sshpubkeyfp") {
		t.Fatal("key still in FreeIPA")
	}
}

var (
	uriRe  = regexp.MustCompile(`name="uri" value="([^"]+)"`)
	uuidRe = regexp.MustCompile(`name="uuid" value="([^"]+)"`)
)

func TestOTPLogin(t *testing.T) {
	stand(t)
	u := newUser(t)
	c := login(t, u.uid, u.password)

	code, body := c.hx("/otptoken/add", url.Values{"desc": {"it phone"}})
	uri, uuid := uriRe.FindStringSubmatch(body), uuidRe.FindStringSubmatch(body)
	if code != http.StatusOK || uri == nil || uuid == nil {
		t.Fatalf("add token: %d %s", code, body)
	}
	key, err := url.Parse(html.UnescapeString(uri[1]))
	if err != nil {
		t.Fatal(err)
	}
	secret := key.Query().Get("secret")
	otp, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := c.hx("/otptoken/verify", url.Values{"otpcode": {otp}, "uri": {html.UnescapeString(uri[1])}, "uuid": {uuid[1]}}); code != http.StatusOK {
		t.Fatalf("verify token: %d %s", code, body)
	}
	if code, body := c.hx("/security/mfa/enable", nil); code != http.StatusOK {
		t.Fatalf("enable 2FA: %d %s", code, body)
	}
	if !strings.Contains(userRaw(t, u.uid), "ipauserauthtype: otp") {
		t.Fatal("FreeIPA auth type is not otp")
	}

	if code := newClient(t).tryLogin(u.uid, u.password, ""); code != http.StatusUnauthorized {
		t.Fatalf("password without OTP: want 401, got %d", code)
	}
	otp, _ = totp.GenerateCode(secret, time.Now())
	if code := newClient(t).tryLogin(u.uid, u.password, otp); code != http.StatusNoContent {
		t.Fatalf("password + OTP: want 204, got %d", code)
	}
}

// A grant ends on the real FreeIPA through the scoped permission from
// docs/guides/groups.md, and a group that lost its member managers shows up
// as a failed expiry instead of silently staying permanent. The sweep runs
// every 5 minutes, so this takes up to about 6.
func TestTimedMembershipExpiresOnRealFreeIPA(t *testing.T) {
	stand(t)

	const perm, priv, role = "Mokey Modify Sponsored Group Membership", "Mokey Expire Memberships", "Mokey User Manager"
	if out, err := ipaCmd("", "permission-show", perm); err == nil {
		t.Fatalf("permission %q already exists on the stand, remove it first: %s", perm, out)
	}
	t.Cleanup(func() {
		_, _ = ipaCmd("", "role-remove-privilege", role, "--privileges="+priv)
		_, _ = ipaCmd("", "privilege-del", priv)
		_, _ = ipaCmd("", "permission-del", perm)
	})
	mustIPA(t, "permission-add", perm, "--right=write", "--attrs=member", "--type=group", "--filter=(membermanager=*)")
	mustIPA(t, "privilege-add", priv, "--desc=Remove expired time-bound memberships")
	mustIPA(t, "privilege-add-permission", priv, "--permissions="+perm)
	mustIPA(t, "role-add-privilege", role, "--privileges="+priv)

	sponsor, expiring, orphaned := newUser(t), newUser(t), newUser(t)
	mustIPA(t, "group-add", "timed"+runID, "--desc=mokey integration")
	mustIPA(t, "group-add", "orphan"+runID, "--desc=mokey integration")
	t.Cleanup(func() {
		_, _ = ipaCmd("", "group-del", "timed"+runID)
		_, _ = ipaCmd("", "group-del", "orphan"+runID)
	})
	for _, g := range []string{"timed" + runID, "orphan" + runID} {
		mustIPA(t, "group-add-member", g, "--users="+sponsor.uid)
		mustIPA(t, "group-add-member-manager", g, "--users="+sponsor.uid)
	}

	sc := login(t, sponsor.uid, sponsor.password)
	grant := func(g string, u *testUser) {
		t.Helper()
		mc := login(t, u.uid, u.password)
		if code, body := mc.hx("/groups/request", url.Values{"group": {g}, "duration": {"1m"}}); code != http.StatusOK {
			t.Fatalf("request %s: %d: %s", g, code, body)
		}
		if code, body := sc.hx("/groups/approve", url.Values{"group": {g}, "username": {u.uid}, "duration": {"1m"}}); code != http.StatusOK {
			t.Fatalf("approve %s: %d: %s", g, code, body)
		}
		if !strings.Contains(mustIPA(t, "group-show", g), u.uid) {
			t.Fatalf("%s is not a member of %s after approval", u.uid, g)
		}
	}
	grant("timed"+runID, expiring)
	grant("orphan"+runID, orphaned)
	// The permission only covers groups that have member managers
	mustIPA(t, "group-remove-member-manager", "orphan"+runID, "--users="+sponsor.uid)

	admin := login(t, "admin", ipaAdminPw)
	var removed, listed bool
	deadline := time.Now().Add(7 * time.Minute)
	for time.Now().Before(deadline) && !(removed && listed) {
		time.Sleep(10 * time.Second)
		removed = !strings.Contains(mustIPA(t, "group-show", "timed"+runID), expiring.uid)
		if _, body := admin.get("/admin"); strings.Contains(body, "orphan"+runID) && strings.Contains(body, orphaned.uid) {
			listed = true
		}
	}
	if !removed {
		t.Error("expired member is still in the sponsored group after 7 minutes")
	}
	if !listed {
		t.Error("failed expiry is not listed on the admin Requests page")
	}
	if !strings.Contains(mustIPA(t, "group-show", "orphan"+runID), orphaned.uid) {
		t.Error("member of the group without member managers was removed")
	}
}
