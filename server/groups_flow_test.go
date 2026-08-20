package server

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestGroupsPageSections(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: []string{"ipausers"}})
	fake.addGroup("chemists", &fakeGroup{Description: "Lab crew", ManagerUsers: []string{"skyler"}})
	fake.addGroup("laundry", &fakeGroup{ManagerUsers: []string{"walter"}})
	fake.addGroup("secret", &fakeGroup{}) // unmanaged: never shown

	router.addGroupRequest("laundry", "jesse", groupRequestJoin)

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.get("/groups")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)

	// my groups
	assert.Contains(body, "ipausers")
	// joinable managed group with its description
	assert.Contains(body, "chemists")
	assert.Contains(body, "Lab crew")
	// group walter manages shows the pending requester
	assert.Contains(body, "laundry")
	assert.Contains(body, "jesse")
	// unmanaged group is invisible
	assert.NotContains(body, "secret")
	// nav tab present
	assert.Contains(body, "groups-tab")
}

func TestGroupRequestJoinFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	fake.addUser("skyler", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{ManagerUsers: []string{"skyler"}})
	fake.addGroup("secret", &fakeGroup{}) // unmanaged

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// request lands in the queue and the page re-renders it as pending
	resp := tc.postForm("/groups/request", url.Values{"group": {"chemists"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	reqs := router.loadGroupRequests("chemists")
	if assert.Len(reqs, 1) {
		assert.Equal("walter", reqs[0].Username)
	}
	assert.Contains(readBody(t, resp), "chemists")

	// duplicate request keeps a single entry
	resp = tc.postForm("/groups/request", url.Values{"group": {"chemists"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Len(router.loadGroupRequests("chemists"), 1)

	// unmanaged group is not requestable
	resp = tc.postForm("/groups/request", url.Values{"group": {"secret"}}, htmx)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	assert.Empty(router.loadGroupRequests("secret"))

	// unknown group
	resp = tc.postForm("/groups/request", url.Values{"group": {"nope"}}, htmx)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
}

func TestGroupApproveDenyFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	fake.addUser("skyler", &fakeUser{Password: "Secret123!"})
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{ManagerUsers: []string{"skyler"}})

	router.addGroupRequest("chemists", "walter", groupRequestJoin)
	router.addGroupRequest("chemists", "jesse", groupRequestJoin)

	tcSponsor := newTestClient(t, app)
	tcSponsor.login("skyler", "Secret123!")

	// approve: member added via the sponsor session, request cleared
	resp := tcSponsor.postForm("/groups/approve", url.Values{
		"group": {"chemists"}, "username": {"walter"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(fake.groups["chemists"].Members, "walter")
	assert.Len(router.loadGroupRequests("chemists"), 1)

	// deny: request cleared, membership unchanged
	resp = tcSponsor.postForm("/groups/deny", url.Values{
		"group": {"chemists"}, "username": {"jesse"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.NotContains(fake.groups["chemists"].Members, "jesse")
	assert.Empty(router.loadGroupRequests("chemists"))

	// approving a non-queued user is refused
	resp = tcSponsor.postForm("/groups/approve", url.Values{
		"group": {"chemists"}, "username": {"jesse"},
	}, htmx)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
}

func TestGroupApproveNonManager(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	fake.addUser("skyler", &fakeUser{Password: "Secret123!"})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{ManagerUsers: []string{"skyler"}})
	router.addGroupRequest("chemists", "jesse", groupRequestJoin)

	// jesse is not a manager; both mokey's check and the fake's
	// group_add_member enforcement refuse
	tc := newTestClient(t, app)
	tc.login("jesse", "Secret123!")
	resp := tc.postForm("/groups/approve", url.Values{
		"group": {"chemists"}, "username": {"jesse"},
	}, htmx)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
	assert.NotContains(fake.groups["chemists"].Members, "jesse")
	assert.Len(router.loadGroupRequests("chemists"), 1)
}

func TestGroupRequestLeaveFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	fake.addUser("skyler", &fakeUser{Password: "Secret123!"})
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: []string{"chemists"}})
	fake.addGroup("chemists", &fakeGroup{ManagerUsers: []string{"skyler"}, Members: []string{"walter"}})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// leave request lands in the queue as a "leave" entry
	resp := tc.postForm("/groups/leave", url.Values{"group": {"chemists"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	reqs := router.loadGroupRequests("chemists")
	if assert.Len(reqs, 1) {
		assert.Equal("walter", reqs[0].Username)
		assert.Equal(groupRequestLeave, reqs[0].Type)
	}

	// duplicate leave request keeps a single entry
	resp = tc.postForm("/groups/leave", url.Values{"group": {"chemists"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Len(router.loadGroupRequests("chemists"), 1)

	tcSponsor := newTestClient(t, app)
	tcSponsor.login("skyler", "Secret123!")

	// approve: member removed via the sponsor session, request cleared
	resp = tcSponsor.postForm("/groups/approve", url.Values{
		"group": {"chemists"}, "username": {"walter"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.NotContains(fake.groups["chemists"].Members, "walter")
	assert.Empty(router.loadGroupRequests("chemists"))
}

func TestGroupLeaveDenyFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	fake.addUser("skyler", &fakeUser{Password: "Secret123!"})
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{ManagerUsers: []string{"skyler"}, Members: []string{"walter"}})
	router.addGroupRequest("chemists", "walter", groupRequestLeave)

	tcSponsor := newTestClient(t, app)
	tcSponsor.login("skyler", "Secret123!")

	resp := tcSponsor.postForm("/groups/deny", url.Values{
		"group": {"chemists"}, "username": {"walter"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(fake.groups["chemists"].Members, "walter")
	assert.Empty(router.loadGroupRequests("chemists"))
}

func TestGroupRequestLeaveNotMember(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	fake.addUser("skyler", &fakeUser{Password: "Secret123!"})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{ManagerUsers: []string{"skyler"}})

	tc := newTestClient(t, app)
	tc.login("jesse", "Secret123!")

	resp := tc.postForm("/groups/leave", url.Values{"group": {"chemists"}}, htmx)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	assert.Empty(router.loadGroupRequests("chemists"))
}

func TestGroupRemoveMemberBySponsor(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)

	fake.addUser("skyler", &fakeUser{Password: "Secret123!"})
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{ManagerUsers: []string{"skyler"}, Members: []string{"walter"}})

	tc := newTestClient(t, app)
	tc.login("skyler", "Secret123!")

	resp := tc.postForm("/groups/remove-member", url.Values{
		"group": {"chemists"}, "username": {"walter"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.NotContains(fake.groups["chemists"].Members, "walter")
}

func TestGroupRemoveMemberNonManager(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)

	fake.addUser("skyler", &fakeUser{Password: "Secret123!"})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{ManagerUsers: []string{"skyler"}, Members: []string{"jesse"}})

	tc := newTestClient(t, app)
	tc.login("jesse", "Secret123!")

	resp := tc.postForm("/groups/remove-member", url.Values{
		"group": {"chemists"}, "username": {"jesse"},
	}, htmx)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
	assert.Contains(fake.groups["chemists"].Members, "jesse")
}

func TestGroupStaleRequestCleanup(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	fake.addUser("skyler", &fakeUser{Password: "Secret123!"})
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	// walter is already a member but a stale request lingers in the queue
	fake.addGroup("chemists", &fakeGroup{ManagerUsers: []string{"skyler"}, Members: []string{"walter"}})
	router.addGroupRequest("chemists", "walter", groupRequestJoin)

	tc := newTestClient(t, app)
	tc.login("skyler", "Secret123!")
	resp := tc.get("/groups")
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// rendering the sponsor queue dropped the stale request from storage
	assert.Empty(router.loadGroupRequests("chemists"))
}
