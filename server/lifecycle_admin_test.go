package server

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLifecycleAdminApp signs in gus, an admin, on a sponsor fake.
func newLifecycleAdminApp(t *testing.T, cfg *lifecycleConfig) (*testClient, *Router, *spDir) {
	t.Helper()
	tc, router, d, _ := newSponsorApp(t, cfg)
	viper.Set("admin.enabled", true)
	viper.Set("admin.users", []string{"gus"})
	d.add("gus", ipatest.User{First: "Gus", Last: "Fring"}, "", time.Time{})
	tc.login("gus", spSecret)
	return tc, router, d
}

func esc(s string) string { return html.EscapeString(s) }

// Review Focus 5
func TestAdminLifecycleOff(t *testing.T) {
	assert := assert.New(t)
	tc, router, d := newLifecycleAdminApp(t, nil)
	d.add("jesse", ipatest.User{}, "", time.Time{})

	assert.NotContains(readBody(t, tc.get("/admin/people")), `href="/admin/lifecycle"`)
	assert.Equal(fiber.StatusNotFound, tc.get("/admin/lifecycle").StatusCode)
	assert.Equal(fiber.StatusNotFound, tc.get("/admin/lifecycle/status", htmx).StatusCode)
	assert.Equal(fiber.StatusNotFound, tc.postForm("/admin/lifecycle/apply", nil, htmx).StatusCode)

	users := readBody(t, tc.get("/admin/users", htmx))
	assert.Contains(users, "/admin/user/reset")
	assert.NotContains(users, "set-expiry")
	assert.NotContains(users, "set-sponsor")
	for _, a := range []string{"set-expiry", "set-sponsor"} {
		resp := tc.postForm("/admin/user/"+a, url.Values{"username": {"jesse"}, "sponsor": {"gus"}, "expires": {"2030-01-01"}}, htmx)
		assert.Equal(fiber.StatusNotFound, resp.StatusCode, a)
	}
	assert.Equal(0, d.modCount())
	assert.Empty(auditEvents(router, "lifecycle sponsor set"))
}

func TestAdminLifecycleNonAdmin(t *testing.T) {
	tc, _, d, _ := newSponsorApp(t, renewalCfg())
	viper.Set("admin.enabled", true)
	viper.Set("admin.users", []string{"gus"})
	d.add("jesse", ipatest.User{}, "", time.Time{})
	tc.login("jesse", spSecret)

	assert.Equal(t, fiber.StatusForbidden, tc.get("/admin/lifecycle").StatusCode)
	assert.Equal(t, fiber.StatusForbidden, tc.get("/admin/lifecycle/status", htmx).StatusCode)
	assert.Equal(t, fiber.StatusForbidden, tc.postForm("/admin/lifecycle/apply", nil, htmx).StatusCode)
	resp := tc.postForm("/admin/user/set-sponsor", url.Values{"username": {"jesse"}, "sponsor": {"jesse"}}, htmx)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	assert.Equal(t, 0, d.modCount())
}

// Review Focus 4
func TestAdminLifecycleHeldPlanApplyOnce(t *testing.T) {
	assert := assert.New(t)
	cfg := assignCfg()
	cfg.MaxChanges = 2
	cfg.Reminders = []int{30, 7, 1}
	tc, router, d := newLifecycleAdminApp(t, cfg)
	now := time.Now()
	d.add("walter", ipatest.User{}, "", time.Time{})
	for _, uid := range []string{"jesse", "skinny", "badger"} {
		d.add(uid, ipatest.User{}, walterDN, time.Time{})
	}
	d.add("gale", ipatest.User{}, "", now.Add(-48*time.Hour))
	d.add("jane", ipatest.User{}, "gale", time.Time{})

	_, held, err := router.lifecycleRun(now, "")
	require.NoError(t, err)
	require.NotNil(t, held)
	require.Equal(t, 0, d.modCount())

	page := readBody(t, tc.get("/admin/lifecycle"))
	assert.Contains(page, `href="/admin/lifecycle" aria-current="page"`)
	assert.Contains(page, `hx-get="/admin/lifecycle/status"`)

	body := readBody(t, tc.get("/admin/lifecycle/status", htmx))
	assert.Contains(body, fmt.Sprintf(T("admin.lifecycle_on_value"), fmt.Sprintf(T("admin.lifecycle_reminder_days"), "30, 7, 1")))
	assert.Contains(body, fmt.Sprintf(T("admin.lifecycle_on_value"), "1 year"))
	assert.Contains(body, esc(fmt.Sprintf(T("admin.lifecycle_held"), "3 changes", 2)))
	// the sweep saw 3; one more account since: the page counts the current plan
	d.add("pete", ipatest.User{}, "walter", time.Time{})
	body = readBody(t, tc.get("/admin/lifecycle/status", htmx))
	assert.Contains(body, esc(fmt.Sprintf(T("admin.lifecycle_held"), "4 changes", 2)))
	assert.Contains(body, "Apply 4 changes")
	assert.Contains(body, esc(fmt.Sprintf(T("admin.lifecycle_why_assign"), "walter")))
	for _, uid := range []string{"jesse", "skinny", "badger", "pete"} {
		assert.Contains(body, ">"+uid+"<")
	}
	assert.Contains(body, `hx-post="/admin/lifecycle/apply"`)
	assert.Contains(body, esc(fmt.Sprintf(T("admin.lifecycle_sponsor_expired_by"), "gale", now.Add(-48*time.Hour).Format("Jan 2, 2006"))))
	assert.Contains(body, ">jane<")

	resp := tc.postForm("/admin/lifecycle/apply", nil, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body = readBody(t, resp)
	assert.Equal(4, d.modCount())
	assert.Contains(body, "4 changes applied.")
	assert.Contains(body, esc(T("admin.lifecycle_nothing_waiting")))
	assert.NotContains(body, `hx-post="/admin/lifecycle/apply"`)
	sum := auditEvents(router, "lifecycle run applied")
	if assert.Len(sum, 1) {
		assert.Equal("gus", sum[0].Actor)
		assert.Equal("4", sum[0].Attrs["count"])
	}

	// a second click, or a second admin
	body = readBody(t, tc.postForm("/admin/lifecycle/apply", nil, htmx))
	assert.Equal(4, d.modCount())
	assert.Contains(body, esc(T("admin.lifecycle_nothing_waiting")))
	assert.NotContains(body, "changes applied")
	assert.Len(auditEvents(router, "lifecycle run applied"), 1)
}

func TestAdminLifecycleStatusOff(t *testing.T) {
	tc, _, _ := newLifecycleAdminApp(t, &lifecycleConfig{Reminders: []int{7}, MaxChanges: 50})
	body := readBody(t, tc.get("/admin/lifecycle/status", htmx))
	assert.Contains(t, body, ">"+T("admin.lifecycle_off")+"<")
	assert.Contains(t, body, esc(T("admin.lifecycle_nothing_waiting")))
}

func TestAdminLifecycleApplyTruncated(t *testing.T) {
	tc, router, d := newLifecycleAdminApp(t, assignCfg())
	d.add("walter", ipatest.User{}, "", time.Time{})
	d.add("jesse", ipatest.User{}, "walter", time.Time{})
	d.truncated = true

	_, held, err := router.lifecycleRun(time.Now(), "")
	require.NoError(t, err)
	require.Nil(t, held)
	require.NoError(t, router.storage.Set(lifecycleHeldKey, []byte(`{"Count":1}`), 0))
	status := readBody(t, tc.get("/admin/lifecycle/status", htmx))
	assert.Contains(t, status, esc(T("admin.helpdesk_truncated")))
	assert.NotContains(t, status, `hx-post="/admin/lifecycle/apply"`)

	body := readBody(t, tc.postForm("/admin/lifecycle/apply", nil, htmx))
	assert.Contains(t, body, esc(T("admin.lifecycle_truncated")))
	assert.Equal(t, 0, d.modCount())
}

func TestAdminSetSponsor(t *testing.T) {
	assert := assert.New(t)
	tc, router, d := newLifecycleAdminApp(t, renewalCfg())
	d.add("walter", ipatest.User{}, "jesse", time.Time{})
	d.add("jesse", ipatest.User{}, "", time.Time{})
	d.add("skinny", ipatest.User{}, "", time.Time{})

	post := func(uid, sponsor string, extra ...string) *fiberResp {
		form := url.Values{"username": {uid}, "sponsor": {sponsor}}
		if len(extra) > 0 {
			form.Set("from", extra[0])
		}
		resp := tc.postForm("/admin/user/set-sponsor", form, htmx)
		return &fiberResp{resp.StatusCode, readBody(t, resp)}
	}

	r := post("jesse", "jesse")
	assert.Equal(fiber.StatusBadRequest, r.code)
	assert.Equal(T("admin.lifecycle_sponsor_self"), r.body)
	r = post("jesse", "walter")
	assert.Equal(fiber.StatusBadRequest, r.code)
	assert.Equal(T("admin.lifecycle_sponsor_loop"), r.body)
	r = post("jesse", "nobody")
	assert.Equal(fiber.StatusBadRequest, r.code)
	assert.Equal(T("admin.lifecycle_sponsor_unknown"), r.body)
	assert.Equal(0, d.modCount())

	r = post("jesse", "skinny")
	assert.Equal(fiber.StatusOK, r.code)
	assert.Contains(r.body, `hx-post="/admin/user/reset"`)
	assert.Contains(r.body, esc(fmt.Sprintf(T("admin.lifecycle_sponsor_set"), "jesse", "skinny")))
	assert.Equal("skinny", d.manager["jesse"])
	set := auditEvents(router, "lifecycle sponsor set")
	if assert.Len(set, 1) {
		assert.Equal("gus", set[0].Actor)
		assert.Equal("jesse", set[0].Username)
		assert.Equal("skinny", set[0].Attrs["sponsor"])
	}
	assert.Empty(auditEvents(router, "admin user action"))

	r = post("jesse", "", "lifecycle")
	assert.Equal(fiber.StatusOK, r.code)
	assert.Contains(r.body, esc(T("admin.lifecycle_waiting")))
	assert.Contains(r.body, esc(fmt.Sprintf(T("admin.lifecycle_sponsor_cleared"), "jesse")))
	assert.Equal("", d.manager["jesse"])
}

type fiberResp struct {
	code int
	body string
}

func TestAdminSetExpiry(t *testing.T) {
	assert := assert.New(t)
	tc, router, d := newLifecycleAdminApp(t, renewalCfg())
	d.add("jesse", ipatest.User{}, "", time.Time{})
	post := func(v string) (int, string) {
		resp := tc.postForm("/admin/user/set-expiry", url.Values{"username": {"jesse"}, "expires": {v}}, htmx)
		return resp.StatusCode, readBody(t, resp)
	}

	future := time.Now().AddDate(0, 2, 0)
	day := future.Format("2006-01-02")
	code, body := post(day)
	assert.Equal(fiber.StatusOK, code)
	want, _ := time.ParseInLocation("2006-01-02", day, time.Local)
	assert.True(want.Equal(d.expiry("jesse")), "got %s", d.expiry("jesse"))
	assert.Contains(body, esc(fmt.Sprintf(T("admin.lifecycle_expiry_set"), "jesse", future.Format("Jan 2, 2006"))))
	set := auditEvents(router, "lifecycle expiry set")
	if assert.Len(set, 1) {
		assert.Equal("gus", set[0].Actor)
	}

	// admins may set a past date: it expires the account
	past := time.Now().AddDate(0, 0, -3)
	code, body = post(past.Format("2006-01-02"))
	assert.Equal(fiber.StatusOK, code)
	assert.True(d.expiry("jesse").Before(time.Now()))
	assert.Contains(body, esc(fmt.Sprintf(T("admin.lifecycle_expiry_expired"), "jesse", past.Format("Jan 2, 2006"))))

	code, body = post("")
	assert.Equal(fiber.StatusOK, code)
	assert.True(d.expiry("jesse").IsZero())
	assert.Contains(body, esc(fmt.Sprintf(T("admin.lifecycle_expiry_cleared"), "jesse")))

	code, body = post("next week")
	assert.Equal(fiber.StatusBadRequest, code)
	assert.Equal(T("admin.lifecycle_expiry_invalid"), body)
	assert.Len(auditEvents(router, "lifecycle expiry set"), 3)

	users := readBody(t, tc.get("/admin/users", htmx))
	assert.Contains(users, `hx-post="/admin/user/set-expiry"`)
	assert.Contains(users, `hx-post="/admin/user/set-sponsor"`)
	assert.Contains(users, esc(T("admin.lifecycle_expiry_confirm")))
}

func TestAdminSetExpiryRefused(t *testing.T) {
	tc, router, d := newLifecycleAdminApp(t, renewalCfg())
	d.add("jesse", ipatest.User{}, "", time.Time{})
	d.refuse = true

	resp := tc.postForm("/admin/user/set-expiry", url.Values{"username": {"jesse"}, "expires": {"2030-01-01"}}, htmx)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, T("admin.lifecycle_write_failed"), readBody(t, resp))
	assert.Empty(t, auditEvents(router, "lifecycle expiry set"))
}

func TestAdminSetExpiryOwnAccount(t *testing.T) {
	tc, router, d := newLifecycleAdminApp(t, renewalCfg())
	post := func(v string) *http.Response {
		return tc.postForm("/admin/user/set-expiry", url.Values{"username": {"gus"}, "expires": {v}}, htmx)
	}

	for _, v := range []string{time.Now().Format("2006-01-02"), time.Now().AddDate(0, 0, -1).Format("2006-01-02")} {
		resp := post(v)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode, v)
		assert.Equal(t, T("admin.lifecycle_expiry_self"), readBody(t, resp))
	}
	assert.Equal(t, 0, d.modCount())
	assert.Empty(t, auditEvents(router, "lifecycle expiry set"))

	assert.Equal(t, fiber.StatusOK, post(time.Now().AddDate(1, 0, 0).Format("2006-01-02")).StatusCode)
	assert.Equal(t, fiber.StatusOK, post("").StatusCode)
	assert.Equal(t, 2, d.modCount())
}

func TestAdminLifecycleActionUnknownUser(t *testing.T) {
	tc, router, d := newLifecycleAdminApp(t, renewalCfg())
	d.add("skinny", ipatest.User{}, "", time.Time{})
	for action, form := range map[string]url.Values{
		"set-expiry":  {"username": {"nobody"}, "expires": {"2030-01-01"}},
		"set-sponsor": {"username": {"nobody"}, "sponsor": {"skinny"}},
	} {
		resp := tc.postForm("/admin/user/"+action, form, htmx)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode, action)
		assert.Equal(t, T("admin.lifecycle_user_unknown"), readBody(t, resp), action)
	}
	resp := tc.postForm("/admin/user/set-sponsor", url.Values{"username": {"nobody"}, "sponsor": {""}}, htmx)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, 0, d.modCount())
	assert.Empty(t, auditEvents(router, "lifecycle sponsor set"))
}
