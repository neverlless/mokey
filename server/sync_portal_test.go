package server

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func portalSyncApp(t *testing.T) (*testClient, *Router, *ipatest.Server) {
	t.Helper()
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
		viper.Set("admin.group", "admins")
		viper.Set("accounts.enable_captcha", false)
	})
	router.sync = &syncConfig{
		ManagedGroup: "google2ipa-managed",
		GroupMapping: map[string][]string{"eng@example.org": {"engineers"}},
		Google:       googleSourceConfig{Domains: []string{"example.org"}},
	}
	fake.AddGroup("google2ipa-managed", ipatest.Group{})
	fake.AddGroup("engineers", ipatest.Group{ManagerUsers: []string{"skyler"}})
	fake.AddUser("skyler", ipatest.User{Password: "Secret123!", Groups: []string{"admins"}})
	fake.AddUser("walter", ipatest.User{
		Password: "Secret123!", Email: "walter@example.org", First: "Walter", Last: "White",
		Groups: []string{"google2ipa-managed", "engineers"},
	})
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	return tc, router, fake
}

func TestManagedSettingsReadOnly(t *testing.T) {
	tc, _, fake := portalSyncApp(t)

	body := readBody(t, tc.get("/account/settings", htmx))
	assert.Contains(t, body, T("sync.managed_by_google"))
	assert.Regexp(t, `<input[^>]*name="first"[^>]*readonly`, body)
	assert.Regexp(t, `<input[^>]*name="last"[^>]*readonly`, body)
	assert.Regexp(t, `<input[^>]*name="email"[^>]*readonly`, body)

	for _, f := range []url.Values{
		{"first": {"Heisenberg"}, "last": {"White"}, "email": {"walter@example.org"}},
		{"first": {"Walter"}, "last": {"Black"}, "email": {"walter@example.org"}},
		{"first": {"Walter"}, "last": {"White"}, "email": {"other@example.org"}},
	} {
		resp := tc.postForm("/account/settings", f, htmx)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	}
	assert.Equal(t, "Walter", fakeUser(fake, "walter").First)

	resp := tc.postForm("/account/settings", url.Values{
		"first": {"Walter"}, "last": {"White"}, "email": {"walter@example.org"}, "displayname": {"Heisenberg"},
	}, htmx)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestUnmanagedSettingsEditable(t *testing.T) {
	tc, router, fake := portalSyncApp(t)
	fake.AddUser("jesse", ipatest.User{Password: "Secret123!", Email: "jesse@example.org", First: "Jesse", Last: "Pinkman"})
	jt := newTestClient(t, tc.app)
	jt.login("jesse", "Secret123!")
	require.True(t, router.sync.on())

	body := readBody(t, jt.get("/account/settings", htmx))
	assert.NotRegexp(t, `<input[^>]*name="first"[^>]*readonly`, body)
	resp := jt.postForm("/account/settings", url.Values{"first": {"Jess"}, "last": {"Pinkman"}, "email": {"jesse@example.org"}}, htmx)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "Jess", fakeUser(fake, "jesse").First)
}

func TestMappedGroupActionsForbidden(t *testing.T) {
	tc, router, _ := portalSyncApp(t)

	for _, p := range []string{"/groups/request", "/groups/leave", "/groups/renew"} {
		resp := tc.postForm(p, url.Values{"group": {"engineers"}}, htmx)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode, p)
	}

	sk := newTestClient(t, tc.app)
	sk.login("skyler", "Secret123!")
	router.addGroupRequest("engineers", "walter", groupRequestLeave, "")
	for _, p := range []string{"/groups/approve", "/groups/deny", "/groups/remove-member"} {
		resp := sk.postForm(p, url.Values{"group": {"engineers"}, "username": {"walter"}}, htmx)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode, p)
	}
}

func TestMappedGroupPageHidesActions(t *testing.T) {
	tc, _, fake := portalSyncApp(t)
	fake.AddGroup("chemists", ipatest.Group{ManagerUsers: []string{"skyler"}})

	body := readBody(t, tc.get("/groups", htmx))
	assert.Contains(t, body, T("sync.synced_from_google"))
	assert.NotContains(t, body, `"group": "engineers"`)
	assert.Contains(t, body, `"group": "chemists"`)

	sk := newTestClient(t, tc.app)
	sk.login("skyler", "Secret123!")
	body = readBody(t, sk.get("/groups", htmx))
	assert.Contains(t, body, T("sync.synced_from_google"))
	assert.NotContains(t, body, "/groups/remove-member")
}

func TestSignupRefusedForGoogleDomain(t *testing.T) {
	tc, _, fake := portalSyncApp(t)
	guest := newTestClient(t, tc.app)
	guest.getCSRF("/signup")

	resp := guest.postForm("/signup", url.Values{
		"username": {"hank"}, "email": {"Hank@Example.ORG"}, "first": {"Hank"}, "last": {"Schrader"},
		"password": {"NewSecret456!"}, "password2": {"NewSecret456!"},
	}, nil)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), T("sync.account_from_google"))
	assert.Nil(t, fakeUser(fake, "hank"))

	resp = guest.postForm("/signup", url.Values{
		"username": {"hank"}, "email": {"hank@other.net"}, "first": {"Hank"}, "last": {"Schrader"},
		"password": {"NewSecret456!"}, "password2": {"NewSecret456!"},
	}, nil)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestInviteRefusedForGoogleDomain(t *testing.T) {
	tc, _, _ := portalSyncApp(t)
	sk := newTestClient(t, tc.app)
	sk.login("skyler", "Secret123!")
	sink := newFakeSMTP(t)

	resp := sk.postForm("/admin/invite", url.Values{"email": {"kim@example.org"}}, htmx)
	assert.Contains(t, readBody(t, resp), T("sync.account_from_google"))
	assert.Equal(t, 0, sink.count())
}

func TestPeopleListMarksSynced(t *testing.T) {
	tc, _, _ := portalSyncApp(t)
	sk := newTestClient(t, tc.app)
	sk.login("skyler", "Secret123!")

	body := readBody(t, sk.get("/admin/users", htmx))
	assert.Contains(t, body, T("sync.synced"))
}
