package server

import (
	"testing"
	"time"

	"github.com/gofiber/storage/memory/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimedMembersRoundTrip(t *testing.T) {
	r := lockedRouter(memory.New())

	got, err := r.loadTimedMembers()
	require.NoError(t, err)
	assert.Empty(t, got)

	until := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, r.putTimedMember(TimedMembership{Group: "g1", Username: "u1", Until: until, GrantedBy: "admin"}))
	require.NoError(t, r.putTimedMember(TimedMembership{Group: "g2", Username: "u1", Until: until}))
	require.NoError(t, r.putTimedMember(TimedMembership{Group: "g1", Username: "u1", Until: until.Add(time.Hour), GrantedBy: "admin2"}))

	all, err := r.loadTimedMembers()
	require.NoError(t, err)
	assert.Len(t, all, 2)

	m, err := r.timedMember("g1", "u1")
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "admin2", m.GrantedBy)
	assert.True(t, m.Until.Equal(until.Add(time.Hour)))

	m, err = r.timedMember("g3", "u1")
	require.NoError(t, err)
	assert.Nil(t, m)

	require.NoError(t, r.dropTimedMember("g1", "u1"))
	require.NoError(t, r.dropTimedMember("g1", "u1"))
	all, err = r.loadTimedMembers()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "g2", all[0].Group)
}

func TestTimedMembersCorruptJSON(t *testing.T) {
	st := memory.New()
	require.NoError(t, st.Set(timedMembersKey, []byte("{not json"), 0))
	r := lockedRouter(st)

	_, err := r.loadTimedMembers()
	assert.Error(t, err)
	assert.Error(t, r.putTimedMember(TimedMembership{Group: "g", Username: "u"}))
	assert.Error(t, r.dropTimedMember("g", "u"))
}

func TestPutTimedMemberStorageFailure(t *testing.T) {
	r := lockedRouter(&failingSetStorage{memory.New()})
	assert.Error(t, r.putTimedMember(TimedMembership{Group: "g", Username: "u"}))
}

func TestHoldStrictRedisDown(t *testing.T) {
	l := newStoreLock(memory.New())
	down := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() { _ = down.Close() })
	l.rdb = down

	start := time.Now()
	release, err := l.holdStrict("k")
	assert.Error(t, err)
	assert.Nil(t, release)
	assert.Less(t, time.Since(start), storeLockWait+time.Second)

	// the failed attempt must not leave the key's local mutex held
	l.rdb = nil
	release, err = l.holdStrict("k")
	require.NoError(t, err)
	release()
}
