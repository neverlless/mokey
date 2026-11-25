package server

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inviteGroupsApp: walter is an admin and manages chemists and engineers
// (sync-owned); skyler manages physics; admins has no managers
func inviteGroupsApp(t *testing.T, on bool, durations bool) (*testClient, *Router, *ipatest.Server, *fakeSMTP) {
	t.Helper()
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
		viper.Set("admin.group", "admins")
		viper.Set("admin.invite_groups", on)
		if durations {
			viper.Set("storage.driver", "sqlite3")
			viper.Set("storage.sqlite3.dbpath", filepath.Join(t.TempDir(), "mokey.db"))
			viper.Set("groups.durations", []string{"7d", "30d"})
		}
	})
	router.sync = &syncConfig{
		ManagedGroup: "google2ipa-managed",
		GroupMapping: map[string][]string{"eng@example.org": {"engineers"}},
	}
	sink := newFakeSMTP(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"admins"}})
	fake.AddUser("skyler", ipatest.User{Password: "Secret123!"})
	fake.AddGroup("chemists", ipatest.Group{ManagerUsers: []string{"walter"}})
	fake.AddGroup("engineers", ipatest.Group{ManagerUsers: []string{"walter"}})
	fake.AddGroup("physics", ipatest.Group{ManagerUsers: []string{"skyler"}})
	allowServiceAccountAdds(t)
	fake.GrantPrivilege(keytabUser, "Modify Group membership")
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	return tc, router, fake, sink
}

func auditEvent(router *Router, msg string) *AuditEvent {
	for _, e := range auditRecent(router.storage, 50) {
		if e.Message == msg {
			return &e
		}
	}
	return nil
}

func groupInviteToken(t *testing.T, router *Router, groups ...InviteGroup) string {
	t.Helper()
	token, err := issueToken("kim@example.com", &Token{Username: "kim@example.com", Email: "kim@example.com", Groups: groups, InvitedBy: "walter"}, TokenInvite, router.storage)
	require.NoError(t, err)
	return token
}

func TestInviteSendGroupsOffRefused(t *testing.T) {
	tc, _, _, sink := inviteGroupsApp(t, false, false)
	resp := tc.postForm("/admin/invite", url.Values{"email": {"kim@example.com"}, "groups": {"chemists"}}, htmx)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), T("admin.invite_groups_off"))
	assert.Equal(t, 0, sink.count())
}

func TestInviteSendGroupsChecked(t *testing.T) {
	tc, router, _, sink := inviteGroupsApp(t, true, true)

	many := []string{}
	for i := range MaxGroups + 1 {
		many = append(many, fmt.Sprintf("group%d", i))
	}
	for name, tt := range map[string]struct {
		form url.Values
		msg  string
	}{
		"unmanaged":   {url.Values{"groups": {"admins"}}, "admin.invite_group_not_allowed"},
		"not manager": {url.Values{"groups": {"physics"}}, "admin.invite_group_not_allowed"},
		"sync owned":  {url.Values{"groups": {"engineers"}}, "admin.invite_group_not_allowed"},
		"missing":     {url.Values{"groups": {"nosuchgroup"}}, "admin.invite_group_not_allowed"},
		"too many":    {url.Values{"groups": many}, "admin.invite_groups_too_many"},
		"duration":    {url.Values{"groups": {"chemists"}, "duration_chemists": {"13d"}}, "admin.invite_group_duration"},
	} {
		tt.form.Set("email", "kim@example.com")
		resp := tc.postForm("/admin/invite", tt.form, htmx)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode, name)
		assert.Contains(t, readBody(t, resp), T(tt.msg), name)
		assert.Equal(t, 0, sink.count(), name)
	}

	resp := tc.postForm("/admin/invite", url.Values{"email": {"kim@example.com"}, "groups": {"chemists", "chemists"}, "duration_chemists": {"7d"}}, htmx)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	require.Equal(t, 1, sink.count())
	claims, err := ParseToken(inviteTokenFromMail(t, sink.all()[0]), TokenInvite, router.storage)
	require.NoError(t, err)
	assert.Equal(t, []InviteGroup{{Name: "chemists", Duration: "7d"}}, claims.Groups)
	assert.Equal(t, "walter", claims.InvitedBy)
}

func TestInviteAcceptAddsGroups(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, false)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists"})

	resp, _ := acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Contains(t, groupMembers(t, fake, "chemists"), "kim")
	e := auditEvent(router, "invited user added to group")
	if assert.NotNil(t, e) {
		assert.Equal(t, "chemists", e.Attrs["group"])
		assert.Equal(t, "kim", e.Username)
		assert.Equal(t, "walter", e.Attrs["invited_by"])
	}
}

func TestInviteAcceptTimeBound(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, true)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists", Duration: "7d"})

	before := time.Now()
	resp, _ := acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Contains(t, groupMembers(t, fake, "chemists"), "kim")
	m, err := router.timedMember("chemists", "kim")
	require.NoError(t, err)
	if assert.NotNil(t, m) {
		assert.WithinDuration(t, before.Add(7*24*time.Hour), m.Until, time.Minute)
		assert.Equal(t, "walter", m.GrantedBy)
	}
}

func TestInviteAcceptSkipsLostRights(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, false)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists"})
	fake.AddGroup("chemists", ipatest.Group{ManagerUsers: []string{"skyler"}})

	resp, _ := acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.NotNil(t, fakeUser(fake, "kim"))
	assert.NotContains(t, groupMembers(t, fake, "chemists"), "kim")
	e := auditEvent(router, "invite group skipped")
	if assert.NotNil(t, e) {
		assert.Equal(t, "not a manager", e.Attrs["reason"])
		assert.Equal(t, "chemists", e.Attrs["group"])
	}
}

func TestInviteAcceptOptionOffSkips(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, false)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists"})
	viper.Set("admin.invite_groups", false)

	resp, _ := acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.NotNil(t, fakeUser(fake, "kim"))
	assert.NotContains(t, groupMembers(t, fake, "chemists"), "kim")
	e := auditEvent(router, "invite group skipped")
	if assert.NotNil(t, e) {
		assert.Equal(t, "disabled", e.Attrs["reason"])
	}
}

func TestInviteAcceptOldToken(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, false)
	token, err := NewToken("kim@example.com", "kim@example.com", TokenInvite, router.storage)
	require.NoError(t, err)

	resp, _ := acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.NotNil(t, fakeUser(fake, "kim"))
	for _, c := range fake.Calls() {
		assert.False(t, c.Method == "group_show" || strings.HasPrefix(c.Method, "group_add_member"), c.Method)
	}
}

func TestInviteAcceptStoreFailRollsBack(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, true)
	allowServiceAccountRemovals(t)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists", Duration: "7d"})
	router.storage = &timedMembersDown{router.storage}

	resp, _ := acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.NotNil(t, fakeUser(fake, "kim"))
	assert.NotContains(t, groupMembers(t, fake, "chemists"), "kim")
}

func TestAdminPeopleInviteGroupList(t *testing.T) {
	tc, _, _, _ := inviteGroupsApp(t, true, true)
	body := readBody(t, tc.get("/admin/people", htmx))
	assert.Contains(t, body, `name="groups" value="chemists"`)
	assert.NotContains(t, body, `value="admins"`)
	assert.NotContains(t, body, `value="engineers"`)
	assert.NotContains(t, body, `value="physics"`)
	assert.Regexp(t, `name="duration_chemists"[^>]*>\s*<option value="">`+T("groups.no_end_date"), body)

	// the form errors re-render keeps the list
	resp := tc.postForm("/admin/invite", url.Values{"email": {"bad"}, "groups": {"chemists"}, "duration_chemists": {"168h0m0s"}}, htmx)
	body = readBody(t, resp)
	assert.Regexp(t, `name="groups" value="chemists"[^>]* checked`, body)
	assert.Regexp(t, `<option value="168h0m0s" selected>`, body)
	assert.NotRegexp(t, `<option value="720h0m0s" selected>`, body)
	assert.Contains(t, body, `aria-labelledby="invite-duration-label-chemists invite-group-label-chemists"`)

	tc, _, _, _ = inviteGroupsApp(t, true, false)
	body = readBody(t, tc.get("/admin/people", htmx))
	assert.Contains(t, body, `name="groups" value="chemists"`)
	assert.NotContains(t, body, "duration_chemists")

	tc, _, _, _ = inviteGroupsApp(t, false, false)
	assert.NotContains(t, readBody(t, tc.get("/admin/people", htmx)), `name="groups"`)
}

func TestInviteSendSuccessClearsGroups(t *testing.T) {
	tc, _, _, sink := inviteGroupsApp(t, true, true)
	resp := tc.postForm("/admin/invite", url.Values{"email": {"kim@example.com"}, "groups": {"chemists"}, "duration_chemists": {"720h0m0s"}}, htmx)
	body := readBody(t, resp)
	require.Equal(t, 1, sink.count())
	assert.Contains(t, body, `name="groups" value="chemists"`)
	assert.NotRegexp(t, `name="groups" value="chemists"[^>]* checked`, body)
	assert.NotContains(t, body, " selected>")
}

func TestInviteAcceptSkipsDisabledInviter(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, false)
	allowServiceAccountAdds(t)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists"})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"admins"}, Locked: true})

	resp, _ := acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.NotNil(t, fakeUser(fake, "kim"))
	assert.NotContains(t, groupMembers(t, fake, "chemists"), "kim")
	e := auditEvent(router, "invite group skipped")
	if assert.NotNil(t, e) {
		assert.Equal(t, "inviter disabled", e.Attrs["reason"])
	}
}

// usedMarkerDown fails every write of a token's used-marker
type usedMarkerDown struct{ fiber.Storage }

func (s *usedMarkerDown) Set(key string, val []byte, exp time.Duration) error {
	if strings.Contains(key, TokenUsedPrefix) {
		return errors.New("storage backend down")
	}
	return s.Storage.Set(key, val, exp)
}

func TestInviteAcceptMarkFailSkipsGroups(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, false)
	allowServiceAccountAdds(t)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists"}, InviteGroup{Name: "physics"})
	router.storage = &usedMarkerDown{router.storage}

	resp, _ := acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.NotNil(t, fakeUser(fake, "kim"))
	assert.NotContains(t, groupMembers(t, fake, "chemists"), "kim")
	skipped := map[string]string{}
	for _, e := range auditRecent(router.storage, 50) {
		if e.Message == "invite group skipped" {
			skipped[e.Attrs["group"]] = e.Attrs["reason"]
		}
	}
	assert.Equal(t, map[string]string{"chemists": "failed", "physics": "failed"}, skipped)
}

func TestInviteGroupsExcludeAdminGroup(t *testing.T) {
	tc, router, fake, sink := inviteGroupsApp(t, true, false)
	allowServiceAccountAdds(t)
	fake.AddGroup("admins", ipatest.Group{ManagerUsers: []string{"walter"}})

	assert.NotContains(t, readBody(t, tc.get("/admin/people", htmx)), `value="admins"`)
	resp := tc.postForm("/admin/invite", url.Values{"email": {"kim@example.com"}, "groups": {"admins"}}, htmx)
	assert.Contains(t, readBody(t, resp), T("admin.invite_group_not_allowed"))
	assert.Equal(t, 0, sink.count())

	token := groupInviteToken(t, router, InviteGroup{Name: "admins"})
	resp, _ = acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.NotContains(t, groupMembers(t, fake, "admins"), "kim")
	e := auditEvent(router, "invite group skipped")
	if assert.NotNil(t, e) {
		assert.Equal(t, "admin group", e.Attrs["reason"])
	}
}
