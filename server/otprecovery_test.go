package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOTPRecoveryQueue(t *testing.T) {
	assert := assert.New(t)
	_, router, _ := newTestApp(t)

	assert.Empty(router.loadOTPRecoveryRequests())
	assert.True(router.addOTPRecoveryRequest("walter"))
	assert.False(router.addOTPRecoveryRequest("walter")) // dedup
	reqs := router.loadOTPRecoveryRequests()
	if assert.Len(reqs, 1) {
		assert.Equal("walter", reqs[0].Username)
		assert.False(reqs[0].RequestedAt.IsZero())
	}
	assert.True(router.removeOTPRecoveryRequest("walter"))
	assert.False(router.removeOTPRecoveryRequest("walter"))
	assert.Empty(router.loadOTPRecoveryRequests())
}
