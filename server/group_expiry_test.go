package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/neverlless/goipa/ipatest"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSweepApp: walter is a member of chemists until `until` on a grant of
// length `grant`; the service account may remove members
func newSweepApp(t *testing.T, until time.Time, grant time.Duration, privileged bool) (*Router, *ipatest.Server) {
	t.Helper()
	_, router, fake := newTimedGroupsApp(t)
	allowServiceAccountRemovals(t)
	if privileged {
		fake.GrantPrivilege(keytabUser, "Modify Group membership")
	}
	_, err := fake.ClientAs("admin").GroupAddMember("chemists", []string{"walter"}, nil)
	require.NoError(t, err)
	require.NoError(t, router.putTimedMember(TimedMembership{
		Group: "chemists", Username: "walter", Until: until, GrantedBy: "skyler", GrantedAt: until.Add(-grant),
	}))
	return router, fake
}

func auditHas(router *Router, msg string) bool {
	for _, e := range auditRecent(router.storage, 50) {
		if e.Message == msg {
			return true
		}
	}
	return false
}

func failures() float64 {
	var m dto.Metric
	_ = NewMetrics().groupExpiryFailures.Write(&m)
	return m.GetCounter().GetValue()
}

func TestSweepRemovesExpired(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()
	router, fake := newSweepApp(t, now.Add(-time.Minute), 8*time.Hour, true)
	sink := newFakeSMTP(t)
	before := failures()

	router.membershipExpirySweep(now, false)

	assert.NotContains(groupMembers(t, fake, "chemists"), "walter")
	m, err := router.timedMember("chemists", "walter")
	require.NoError(t, err)
	assert.Nil(m)
	assert.True(auditHas(router, "group membership expired"))
	assert.Equal(before, failures())
	assert.Empty(router.expiryFailures())
	msgs := sink.all()
	if assert.Len(msgs, 1) {
		assert.Contains(msgs[0], T("email_template.group_expired_subject")+"chemists")
	}
}

func TestSweepKeepsFuture(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()
	router, fake := newSweepApp(t, now.Add(time.Hour), 8*time.Hour, true)

	router.membershipExpirySweep(now, false)

	assert.Contains(groupMembers(t, fake, "chemists"), "walter")
	m, err := router.timedMember("chemists", "walter")
	require.NoError(t, err)
	assert.NotNil(m)
}

func TestSweepNotAMemberDropsRecord(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()
	router, fake := newSweepApp(t, now.Add(-time.Minute), 8*time.Hour, true)
	_, err := fake.ClientAs("admin").GroupRemoveMember("chemists", []string{"walter"}, nil)
	require.NoError(t, err)

	router.membershipExpirySweep(now, false)

	m, err := router.timedMember("chemists", "walter")
	require.NoError(t, err)
	assert.Nil(m)
	assert.Empty(router.expiryFailures())
}

func TestSweepRefusedKeepsRecord(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()
	router, fake := newSweepApp(t, now.Add(-time.Minute), 8*time.Hour, false)
	before := failures()

	router.membershipExpirySweep(now, false)

	assert.Contains(groupMembers(t, fake, "chemists"), "walter")
	m, err := router.timedMember("chemists", "walter")
	require.NoError(t, err)
	assert.NotNil(m)
	assert.Equal(before+1, failures())
	assert.True(auditHas(router, "group membership expiry failed"))
	fails := router.expiryFailures()
	if assert.Len(fails, 1) {
		assert.Equal("chemists", fails[0].Group)
		assert.Equal("walter", fails[0].Username)
		assert.Contains(fails[0].Err, "Mokey Expire Memberships")
	}

	// a repeated failure keeps the first Since
	router.membershipExpirySweep(now.Add(5*time.Minute), false)
	if fails2 := router.expiryFailures(); assert.Len(fails2, 1) && len(fails) == 1 {
		assert.Equal(fails[0].Since, fails2[0].Since)
	}

	fake.GrantPrivilege(keytabUser, "Modify Group membership")
	router.membershipExpirySweep(now.Add(10*time.Minute), false)
	assert.NotContains(groupMembers(t, fake, "chemists"), "walter")
	assert.Empty(router.expiryFailures())
}

func TestSweepRunsWhenFeatureOff(t *testing.T) {
	assert := assert.New(t)
	_, router, fake := newTestApp(t)
	assert.False(router.groupExpiry.Enabled())
	assert.False(router.shouldRunMembershipExpiry())

	started := 0
	orig := startLoop
	startLoop = func(func()) { started++ }
	t.Cleanup(func() { startLoop = orig })

	router.StartMembershipExpiry()
	assert.Equal(0, started)

	fake.AddUser("walter", ipatest.User{})
	fake.AddGroup("chemists", ipatest.Group{ManagerUsers: []string{"admin"}})
	_, err := fake.ClientAs("admin").GroupAddMember("chemists", []string{"walter"}, nil)
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, router.putTimedMember(TimedMembership{Group: "chemists", Username: "walter", Until: now.Add(-time.Minute), GrantedAt: now.Add(-time.Hour)}))

	assert.True(router.shouldRunMembershipExpiry())
	router.StartMembershipExpiry()
	assert.Equal(1, started)

	allowServiceAccountRemovals(t)
	fake.GrantPrivilege(keytabUser, "Modify Group membership")
	router.membershipExpirySweep(now, true)
	assert.NotContains(groupMembers(t, fake, "chemists"), "walter")
}

func TestReconcileDropsOutOfBandRemoval(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()
	router, fake := newSweepApp(t, now.Add(time.Hour), 8*time.Hour, true)
	_, err := fake.ClientAs("admin").GroupRemoveMember("chemists", []string{"walter"}, nil)
	require.NoError(t, err)

	router.membershipExpirySweep(now, false)
	m, err := router.timedMember("chemists", "walter")
	require.NoError(t, err)
	assert.NotNil(m)

	router.membershipExpirySweep(now, true)
	m, err = router.timedMember("chemists", "walter")
	require.NoError(t, err)
	assert.Nil(m)

	for _, c := range fake.Calls() {
		if c.User == keytabUser {
			assert.NotEqual("group_remove_member", c.Method)
		}
	}
}

func TestExpiryReminderOnce(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()
	until := now.Add(20 * time.Hour)
	router, _ := newSweepApp(t, until, 7*24*time.Hour, true)
	router.groupExpiry.Reminders = []time.Duration{24 * time.Hour}
	sink := newFakeSMTP(t)

	router.membershipExpirySweep(now, false)
	msgs := sink.all()
	if assert.Len(msgs, 1) {
		assert.Contains(msgs[0], T("email_template.group_expiry_reminder_subject")+"chemists")
		assert.Contains(msgs[0], "walter@example.com")
	}
	marker, _ := router.storage.Get(membershipReminderMarker(TimedMembership{Group: "chemists", Username: "walter", Until: until}, 24*time.Hour))
	assert.NotNil(marker)

	router.membershipExpirySweep(now.Add(time.Minute), false)
	assert.Equal(1, sink.count())

	// an 8h grant is shorter than the 1d lead: no reminder
	require.NoError(t, router.putTimedMember(TimedMembership{
		Group: "chemists", Username: "walter", Until: now.Add(7 * time.Hour), GrantedAt: now.Add(-time.Hour),
	}))
	router.membershipExpirySweep(now, false)
	assert.Equal(1, sink.count())
}

func TestSweepSkipsOnStoreFailure(t *testing.T) {
	assert := assert.New(t)
	now := time.Now()
	router, fake := newSweepApp(t, now.Add(-time.Minute), 8*time.Hour, true)
	calls := len(fake.Calls())

	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(saved) })
	router.storage = &failingStorage{router.storage}

	router.membershipExpirySweep(now, true)

	assert.Equal(calls, len(fake.Calls()))
	assert.Contains(groupMembers(t, fake, "chemists"), "walter")
	logged := false
	dec := json.NewDecoder(&logs)
	for {
		var e map[string]any
		if dec.Decode(&e) != nil {
			break
		}
		if e["level"] == "ERROR" && strings.Contains(e["msg"].(string), "expiry") {
			logged = true
		}
	}
	assert.True(logged, logs.String())
}
