package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupRequestQueue(t *testing.T) {
	assert := assert.New(t)
	_, router, _ := newTestApp(t)

	assert.Empty(router.loadGroupRequests("chemists"))

	assert.True(router.addGroupRequest("chemists", "jesse", groupRequestJoin))
	// duplicate is rejected, queue keeps one entry
	assert.False(router.addGroupRequest("chemists", "jesse", groupRequestJoin))
	reqs := router.loadGroupRequests("chemists")
	if assert.Len(reqs, 1) {
		assert.Equal("jesse", reqs[0].Username)
		assert.Equal(groupRequestJoin, reqs[0].Type)
		assert.False(reqs[0].RequestedAt.IsZero())
	}

	// queues are per group
	assert.True(router.addGroupRequest("lab", "jesse", groupRequestLeave))
	assert.Len(router.loadGroupRequests("chemists"), 1)
	if assert.Len(router.loadGroupRequests("lab"), 1) {
		assert.Equal(groupRequestLeave, router.loadGroupRequests("lab")[0].Type)
	}

	assert.True(router.removeGroupRequest("chemists", "jesse"))
	assert.False(router.removeGroupRequest("chemists", "jesse"))
	assert.Empty(router.loadGroupRequests("chemists"))
	assert.Len(router.loadGroupRequests("lab"), 1)
}
