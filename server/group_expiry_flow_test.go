package server

import (
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTimedGroupsApp: skyler sponsors chemists and prod-sudo (max 8h),
// walter can ask to join
func newTimedGroupsApp(t *testing.T) (*fiber.App, *Router, *ipatest.Server) {
	t.Helper()
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("storage.driver", "sqlite3")
		viper.Set("storage.sqlite3.dbpath", filepath.Join(t.TempDir(), "mokey.db"))
		viper.Set("groups.durations", []string{"8h", "7d", "30d"})
		viper.Set("groups.rules", []any{map[string]any{"group": "prod-sudo", "max": "8h"}})
	})
	fake.AddUser("skyler", ipatest.User{Password: "Secret123!"})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	fake.AddGroup("chemists", ipatest.Group{ManagerUsers: []string{"skyler"}})
	fake.AddGroup("prod-sudo", ipatest.Group{ManagerUsers: []string{"skyler"}})
	return app, router, fake
}

func approveAs(t *testing.T, app *fiber.App, sponsor string, form url.Values) (int, string) {
	t.Helper()
	tc := newTestClient(t, app)
	tc.login(sponsor, "Secret123!")
	resp := tc.postForm("/groups/approve", form, htmx)
	return resp.StatusCode, readBody(t, resp)
}

func TestTimedJoinRequestValidatesDuration(t *testing.T) {
	assert := assert.New(t)
	app, router, _ := newTimedGroupsApp(t)

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/groups/request", url.Values{"group": {"chemists"}, "duration": {"7d"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	reqs := router.loadGroupRequests("chemists")
	if assert.Len(reqs, 1) {
		assert.Equal("7d", reqs[0].Duration)
	}

	for _, tt := range []struct{ group, duration string }{
		{"chemists", "5d"},  // not configured
		{"prod-sudo", ""},   // ruled: no permanent
		{"prod-sudo", "7d"}, // above the rule max
	} {
		router.removeGroupRequest(tt.group, "walter")
		resp = tc.postForm("/groups/request", url.Values{"group": {tt.group}, "duration": {tt.duration}}, htmx)
		assert.Equal(fiber.StatusBadRequest, resp.StatusCode, tt)
		assert.Empty(router.loadGroupRequests(tt.group), tt)
	}
}

func TestTimedApproveShortens(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTimedGroupsApp(t)
	router.addGroupRequest("chemists", "walter", groupRequestJoin, "7d")

	code, _ := approveAs(t, app, "skyler", url.Values{"group": {"chemists"}, "username": {"walter"}, "duration": {"8h"}})
	assert.Equal(fiber.StatusOK, code)
	assert.Contains(groupMembers(t, fake, "chemists"), "walter")
	assert.Empty(router.loadGroupRequests("chemists"))

	m, err := router.timedMember("chemists", "walter")
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.WithinDuration(time.Now().Add(8*time.Hour), m.Until, time.Minute)
	assert.Equal("skyler", m.GrantedBy)
}

func TestTimedApproveCannotLengthen(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTimedGroupsApp(t)
	router.addGroupRequest("chemists", "walter", groupRequestJoin, "8h")

	for _, d := range []string{"7d", ""} {
		code, _ := approveAs(t, app, "skyler", url.Values{"group": {"chemists"}, "username": {"walter"}, "duration": {d}})
		assert.Equal(fiber.StatusBadRequest, code, d)
	}
	assert.NotContains(groupMembers(t, fake, "chemists"), "walter")
	assert.Len(router.loadGroupRequests("chemists"), 1)
}

func TestTimedApproveDefaultsToRequested(t *testing.T) {
	assert := assert.New(t)
	app, router, _ := newTimedGroupsApp(t)
	router.addGroupRequest("chemists", "walter", groupRequestJoin, "7d")

	code, _ := approveAs(t, app, "skyler", url.Values{"group": {"chemists"}, "username": {"walter"}})
	assert.Equal(fiber.StatusOK, code)
	m, err := router.timedMember("chemists", "walter")
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.WithinDuration(time.Now().Add(7*24*time.Hour), m.Until, time.Minute)
}

func TestTimedApproveAlreadyMember(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTimedGroupsApp(t)
	router.addGroupRequest("chemists", "walter", groupRequestJoin, "7d")
	_, err := fake.ClientAs("admin").GroupAddMember("chemists", []string{"walter"}, nil)
	require.NoError(t, err)

	code, body := approveAs(t, app, "skyler", url.Values{"group": {"chemists"}, "username": {"walter"}, "duration": {"7d"}})
	assert.Equal(fiber.StatusOK, code)
	assert.Contains(body, T("groups.already_member_no_end"))
	assert.Empty(router.loadGroupRequests("chemists"))
	m, err := router.timedMember("chemists", "walter")
	require.NoError(t, err)
	assert.Nil(m)
}

// timedMembersDown fails every write to the time-bound membership key and
// nothing else
type timedMembersDown struct{ fiber.Storage }

func (s *timedMembersDown) Set(key string, val []byte, exp time.Duration) error {
	if key == timedMembersKey {
		return errors.New("storage backend down")
	}
	return s.Storage.Set(key, val, exp)
}

func TestTimedApproveRollsBackOnStoreFailure(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTimedGroupsApp(t)
	router.addGroupRequest("chemists", "walter", groupRequestJoin, "7d")
	router.storage = &timedMembersDown{router.storage}

	code, body := approveAs(t, app, "skyler", url.Values{"group": {"chemists"}, "username": {"walter"}, "duration": {"7d"}})
	assert.Equal(fiber.StatusInternalServerError, code)
	assert.Equal(T("groups.expiry_store_failed"), body)
	assert.NotContains(groupMembers(t, fake, "chemists"), "walter")
	assert.Len(router.loadGroupRequests("chemists"), 1)

	var removedBy string
	for _, c := range fake.Calls() {
		if c.Method == "group_remove_member" {
			removedBy = c.User
		}
	}
	assert.Equal("skyler", removedBy)
}

func TestPermanentRequestUnchanged(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)
	fake.AddUser("skyler", ipatest.User{Password: "Secret123!"})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	fake.AddUser("jesse", ipatest.User{Password: "Secret123!"})
	fake.AddGroup("chemists", ipatest.Group{ManagerUsers: []string{"skyler"}})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	resp := tc.postForm("/groups/request", url.Values{"group": {"chemists"}, "duration": {"7d"}}, htmx)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	resp = tc.postForm("/groups/request", url.Values{"group": {"chemists"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	reqs := router.loadGroupRequests("chemists")
	if assert.Len(reqs, 1) {
		assert.Empty(reqs[0].Duration)
	}

	// a request queued while the feature was on is granted permanently
	router.addGroupRequest("chemists", "jesse", groupRequestJoin, "7d")

	for _, u := range []string{"walter", "jesse"} {
		code, _ := approveAs(t, app, "skyler", url.Values{"group": {"chemists"}, "username": {u}})
		assert.Equal(fiber.StatusOK, code, u)
		assert.Contains(groupMembers(t, fake, "chemists"), u)
	}
	raw, err := router.storage.Get(timedMembersKey)
	require.NoError(t, err)
	assert.Nil(raw)
}

// the Apps page has no picker: it asks for the longest offered grant, or
// for no end date when that is offered
func TestTimedAppRequestDuration(t *testing.T) {
	assert := assert.New(t)
	app, router, _ := newAppsTestApp(t, func() {
		viper.Set("storage.driver", "sqlite3")
		viper.Set("storage.sqlite3.dbpath", filepath.Join(t.TempDir(), "mokey.db"))
		viper.Set("groups.durations", []string{"8h", "7d"})
		viper.Set("groups.rules", []any{map[string]any{"group": "vault-users", "max": "1d"}})
	})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	tc.get("/apps")

	for _, tt := range []struct{ client, group, want string }{
		{"grafana", "grafana-users", ""},
		{"vault", "vault-users", "8h0m0s"},
	} {
		resp := tc.postForm("/apps/request", url.Values{"client": {tt.client}}, htmx)
		assert.Equal(fiber.StatusOK, resp.StatusCode, tt.client)
		reqs := router.loadGroupRequests(tt.group)
		if assert.Len(reqs, 1, tt.client) {
			assert.Equal(tt.want, reqs[0].Duration, tt.client)
		}
	}
}
