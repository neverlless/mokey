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

	router.addGroupRequest("laundry", "jesse")

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
