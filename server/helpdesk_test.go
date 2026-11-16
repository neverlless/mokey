package server

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type helpdeskFixture struct {
	uid        string
	expires    time.Duration // from now; 0 = no expiry
	failed     int
	lastFailed time.Duration // ago
	lastLogin  time.Duration // ago; 0 = never recorded
	pwdChange  time.Duration // ago; 0 = never set
	disabled   bool
}

func ipaTime(t time.Time) []map[string]string {
	return []map[string]string{{"__datetime__": t.UTC().Format(ipa.IpaDatetimeFormat)}}
}

// ipatest's user_find does not render the Kerberos login attributes, so the
// helpdesk directory is served by an override; failed counts of users that
// exist in the fake follow it, so user_unlock shows up
func serveHelpdeskUsers(fake *ipatest.Server, truncated bool, users ...helpdeskFixture) {
	fake.Handle("user_find", func(ipatest.Call) (any, *ipa.IpaError) {
		now := time.Now()
		recs := []map[string]any{}
		for _, u := range users {
			rec := map[string]any{
				"uid":           []string{u.uid},
				"givenname":     []string{"First"},
				"sn":            []string{u.uid},
				"mail":          []string{u.uid + "@example.com"},
				"nsaccountlock": u.disabled,
			}
			if u.expires != 0 {
				rec["krbpasswordexpiration"] = ipaTime(now.Add(u.expires))
			}
			failed := u.failed
			if fu := fakeUser(fake, u.uid); fu != nil && failed > 0 {
				failed = fu.FailedLogins
			}
			if failed > 0 {
				rec["krbloginfailedcount"] = []string{strconv.Itoa(failed)}
				rec["krblastfailedauth"] = ipaTime(now.Add(-u.lastFailed))
			}
			if u.pwdChange != 0 {
				rec["krblastpwdchange"] = ipaTime(now.Add(-u.pwdChange))
			}
			if u.lastLogin != 0 {
				rec["krblastsuccessfulauth"] = ipaTime(now.Add(-u.lastLogin))
			}
			recs = append(recs, rec)
		}
		return map[string]any{"result": recs, "count": len(recs), "truncated": truncated, "summary": nil}, nil
	})
}

// ipatest answers config_show as FreeIPA ships: with KDC:Disable Last Success
func trackLastLogin(fake *ipatest.Server, masters ...string) {
	fake.Handle("config_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{
			"ipaconfigstring":   []string{"AllowNThash"},
			"ipa_master_server": masters,
		}, "summary": nil}, nil
	})
}

var helpdeskRowPattern = regexp.MustCompile(`<strong>([^<]+)</strong>`)

func helpdeskList(t *testing.T, tc *testClient, view string) ([]string, string) {
	t.Helper()
	resp := tc.get("/admin/helpdesk?view="+view, htmx)
	body := readBody(t, resp)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("helpdesk %s: status %d", view, resp.StatusCode)
	}
	uids := []string{}
	for _, m := range helpdeskRowPattern.FindAllStringSubmatch(body, -1) {
		uids = append(uids, m[1])
	}
	return uids, body
}

func newHelpdeskApp(t *testing.T) (*fiber.App, *Router, *ipatest.Server, *testClient) {
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
	})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"admins"}})
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	return app, router, fake, tc
}

func TestAdminHelpdeskViews(t *testing.T) {
	assert := assert.New(t)
	_, _, fake, tc := newHelpdeskApp(t)

	trackLastLogin(fake)
	// global policy: 6 failures lock for 10 minutes
	fake.AddUser("jesse", ipatest.User{FailedLogins: 6})
	fake.AddUser("mike", ipatest.User{FailedLogins: 6})
	fake.AddUser("todd", ipatest.User{FailedLogins: 1})
	day := 24 * time.Hour
	serveHelpdeskUsers(fake, false,
		helpdeskFixture{uid: "saul", expires: 3 * day, lastLogin: day},
		helpdeskFixture{uid: "gus", expires: -day, disabled: true},
		helpdeskFixture{uid: "hank", expires: 60 * day},
		helpdeskFixture{uid: "jesse", failed: 6, lastFailed: time.Minute},
		helpdeskFixture{uid: "mike", failed: 6, lastFailed: time.Hour}, // lockout ran out
		helpdeskFixture{uid: "todd", failed: 1, lastFailed: time.Minute},
		helpdeskFixture{uid: "lydia", disabled: true},
		helpdeskFixture{uid: "skinny", lastLogin: 200 * day},
	)

	expiring, _ := helpdeskList(t, tc, "expiring")
	assert.Equal([]string{"saul"}, expiring)

	expired, body := helpdeskList(t, tc, "expired")
	assert.Equal([]string{"gus"}, expired)
	assert.Contains(body, T("admin.blocked"))

	// lydia is disabled (nsaccountlock), not locked out
	locked, _ := helpdeskList(t, tc, "locked")
	assert.Equal([]string{"jesse"}, locked)

	inactive, body := helpdeskList(t, tc, "inactive")
	assert.Equal([]string{"skinny"}, inactive)
	assert.Contains(body, T("admin.helpdesk_source_ipa"))
	assert.NotContains(body, T("admin.helpdesk_inactive_kdc_hint"))
	assert.NotContains(body, T("admin.helpdesk_truncated"))
}

func TestAdminHelpdeskInactiveSources(t *testing.T) {
	assert := assert.New(t)
	_, router, fake, tc := newHelpdeskApp(t)
	day := 24 * time.Hour
	now := time.Now()

	// FreeIPA's default config: the KDC does not record logins
	router.recordSignIn("skinny", now.Add(-100*day))
	router.recordSignIn("badger", now.Add(-100*day))
	router.recordSignIn("huell", now.Add(-100*day))
	serveHelpdeskUsers(fake, false,
		helpdeskFixture{uid: "skinny"},                                      // only an old mokey sign-in
		helpdeskFixture{uid: "badger", pwdChange: 5 * day},                  // recent password change wins
		helpdeskFixture{uid: "huell", pwdChange: 200 * day, lastLogin: day}, // FreeIPA login wins
		helpdeskFixture{uid: "kim", pwdChange: 150 * day},
		helpdeskFixture{uid: "lalo"}, // nothing anywhere
	)

	uids, body := helpdeskList(t, tc, "inactive")
	assert.Equal([]string{"kim", "skinny"}, uids)
	assert.Contains(body, T("admin.helpdesk_source_mokey"))
	assert.Contains(body, T("admin.helpdesk_source_password"))
	assert.Contains(body, fmt.Sprintf(T("admin.helpdesk_no_activity"), 1))
	assert.Contains(body, T("admin.helpdesk_inactive_kdc_hint"))
	assert.Contains(body, `ipa config-mod --delattr ipaconfigstring="KDC:Disable Last Success"`)
}

func TestAdminHelpdeskReadsEveryMaster(t *testing.T) {
	assert := assert.New(t)
	_, _, fake, tc := newHelpdeskApp(t)
	day := 24 * time.Hour

	other := ipatest.NewServer(t)
	other.GrantPrivilege(keytabUser, "User Administrators")
	other.SetNegotiateUser(keytabUser)
	serveHelpdeskUsers(other, false, helpdeskFixture{uid: "skinny", lastLogin: day})

	self, _, _ := strings.Cut(fake.Host(), ":")
	asked := []string{}
	orig := newIPAClientForHost
	t.Cleanup(func() { newIPAClientForHost = orig })
	newIPAClientForHost = func(host string) (*ipa.Client, error) {
		asked = append(asked, host)
		if host == "ipa2.example.test" {
			return newFakeClient(other), nil
		}
		return nil, errors.New("unreachable")
	}

	trackLastLogin(fake, self, "ipa2.example.test", "ipa3.example.test")
	serveHelpdeskUsers(fake, false,
		helpdeskFixture{uid: "skinny", lastLogin: 200 * day},
		helpdeskFixture{uid: "saul", lastLogin: 200 * day},
	)

	uids, body := helpdeskList(t, tc, "inactive")
	assert.Equal([]string{"saul"}, uids)
	assert.ElementsMatch([]string{"ipa2.example.test", "ipa3.example.test"}, asked)
	assert.Contains(body, fmt.Sprintf(T("admin.helpdesk_masters_unreachable"), "ipa3.example.test"))
	assert.NotContains(body, T("admin.helpdesk_inactive_kdc_hint"))
}

func TestAdminHelpdeskTruncated(t *testing.T) {
	_, _, fake, tc := newHelpdeskApp(t)
	serveHelpdeskUsers(fake, true, helpdeskFixture{uid: "saul", expires: time.Hour})
	uids, body := helpdeskList(t, tc, "expiring")
	assert.Equal(t, []string{"saul"}, uids)
	assert.Contains(t, body, T("admin.helpdesk_truncated"))
}

func TestAdminHelpdeskUnlock(t *testing.T) {
	assert := assert.New(t)
	_, router, fake, tc := newHelpdeskApp(t)
	fake.AddUser("jesse", ipatest.User{FailedLogins: 6})
	serveHelpdeskUsers(fake, false, helpdeskFixture{uid: "jesse", failed: 6, lastFailed: time.Minute})

	// CSRF-protected like every admin action
	csrf := tc.csrf
	tc.csrf = ""
	resp := tc.postForm("/admin/user/unlock?helpdesk=locked", url.Values{"username": {"jesse"}}, htmx)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
	assert.Equal(6, fakeUser(fake, "jesse").FailedLogins)
	tc.csrf = csrf

	resp = tc.postForm("/admin/user/unlock?helpdesk=locked", url.Values{"username": {"jesse"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)
	assert.Equal(0, fakeUser(fake, "jesse").FailedLogins)
	assert.NotContains(body, "<strong>jesse</strong>")
	assert.Contains(body, T("admin.helpdesk_view_locked"))

	audited := false
	for _, e := range auditRecent(router.storage, 50) {
		if e.Username == "jesse" && e.Actor == "walter" {
			audited = true
		}
	}
	assert.True(audited, "unlock not in the audit log")
}

func TestAdminHelpdeskRequiresAdmin(t *testing.T) {
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
	})
	fake.AddUser("jesse", ipatest.User{Password: "Secret123!"})
	tc := newTestClient(t, app)
	tc.login("jesse", "Secret123!")

	resp := tc.get("/admin/helpdesk", htmx)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	resp = tc.postForm("/admin/user/unlock?helpdesk=locked", url.Values{"username": {"jesse"}}, htmx)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
}
