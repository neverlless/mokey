package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var lcNow = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func lcDays(n int) time.Time { return lcNow.Add(time.Duration(n) * 24 * time.Hour) }

func lcByUID(cs []lcChange) map[string]lcChange {
	m := map[string]lcChange{}
	for _, c := range cs {
		m[c.UID] = c
	}
	return m
}

func TestPlanLifecycleAssign(t *testing.T) {
	cfg := &lifecycleConfig{Renewal: 365 * 24 * time.Hour, AssignMissing: true, MaxChanges: 50}
	accts := []lcAccount{
		{UID: "s"},
		{UID: "a", Sponsor: "s"},
		{UID: "off", Sponsor: "s", Disabled: true},
		{UID: "free"},
	}
	ch, exp := planLifecycle(accts, lcNow, cfg)
	assert.Empty(t, exp)
	require.Len(t, ch, 1)
	assert.Equal(t, lcChange{UID: "a", To: lcNow.Add(cfg.Renewal), Reason: "assign"}, ch[0])

	accts[0].Expires = lcDays(30)
	ch, _ = planLifecycle(accts, lcNow, cfg)
	require.Len(t, ch, 1)
	assert.Equal(t, lcDays(30), ch[0].To)

	cfg.AssignMissing = false
	ch, _ = planLifecycle(accts, lcNow, cfg)
	assert.Empty(t, ch)
}

func TestPlanLifecycleCascade(t *testing.T) {
	cfg := &lifecycleConfig{Renewal: 365 * 24 * time.Hour, MaxChanges: 50}
	t.Run("future sponsor caps", func(t *testing.T) {
		ch, exp := planLifecycle([]lcAccount{
			{UID: "s", Expires: lcDays(10)},
			{UID: "a", Sponsor: "s", Expires: lcDays(100)},
			{UID: "b", Sponsor: "s", Expires: lcDays(5)},
		}, lcNow, cfg)
		assert.Empty(t, exp)
		require.Len(t, ch, 1)
		assert.Equal(t, lcChange{UID: "a", From: lcDays(100), To: lcDays(10), Reason: "sponsor_cap"}, ch[0])
	})
	t.Run("past sponsor is listed, not applied", func(t *testing.T) {
		ch, exp := planLifecycle([]lcAccount{
			{UID: "s", Expires: lcDays(-3)},
			{UID: "a", Sponsor: "s", Expires: lcDays(100)},
		}, lcNow, cfg)
		assert.Empty(t, ch)
		assert.Equal(t, []string{"a"}, exp)
	})
	t.Run("sponsor without expiry", func(t *testing.T) {
		ch, exp := planLifecycle([]lcAccount{
			{UID: "s"},
			{UID: "a", Sponsor: "s", Expires: lcDays(100)},
		}, lcNow, cfg)
		assert.Empty(t, ch)
		assert.Empty(t, exp)
	})
	t.Run("disabled account untouched, disabled sponsor still caps", func(t *testing.T) {
		ch, _ := planLifecycle([]lcAccount{
			{UID: "s", Expires: lcDays(10), Disabled: true},
			{UID: "a", Sponsor: "s", Expires: lcDays(100)},
			{UID: "off", Sponsor: "s", Expires: lcDays(100), Disabled: true},
		}, lcNow, cfg)
		require.Len(t, ch, 1)
		assert.Equal(t, "a", ch[0].UID)
	})
}

func TestPlanLifecycleChain(t *testing.T) {
	cfg := &lifecycleConfig{MaxChanges: 50}
	ch, _ := planLifecycle([]lcAccount{
		{UID: "c", Sponsor: "b", Expires: lcDays(300)},
		{UID: "b", Sponsor: "a", Expires: lcDays(200)},
		{UID: "a", Expires: lcDays(10)},
	}, lcNow, cfg)
	m := lcByUID(ch)
	assert.Equal(t, lcDays(10), m["b"].To)
	assert.Equal(t, lcDays(10), m["c"].To)
	assert.Equal(t, lcDays(300), m["c"].From)
	assert.Equal(t, []string{"b", "c"}, []string{ch[0].UID, ch[1].UID})

	long := []lcAccount{{UID: "n00", Expires: lcDays(10)}}
	for i := 1; i < 30; i++ {
		long = append(long, lcAccount{UID: fmt.Sprintf("n%02d", i), Sponsor: fmt.Sprintf("n%02d", i-1), Expires: lcDays(100)})
	}
	ch, _ = planLifecycle(long, lcNow, cfg)
	assert.Len(t, ch, 29)

	// sponsors sort after their people: one hop per pass, the 10-pass bound cuts it
	rev := []lcAccount{{UID: "n99", Expires: lcDays(10)}}
	for i := 1; i < 30; i++ {
		rev = append(rev, lcAccount{UID: fmt.Sprintf("n%02d", 99-i), Sponsor: fmt.Sprintf("n%02d", 100-i), Expires: lcDays(100)})
	}
	ch, _ = planLifecycle(rev, lcNow, cfg)
	assert.Len(t, ch, 10)

	ch, _ = planLifecycle([]lcAccount{
		{UID: "a", Sponsor: "b", Expires: lcDays(10)},
		{UID: "b", Sponsor: "a", Expires: lcDays(20)},
	}, lcNow, cfg)
	require.Len(t, ch, 1)
	assert.Equal(t, "b", ch[0].UID)
	assert.Equal(t, lcDays(10), ch[0].To)
}

func TestExtendTarget(t *testing.T) {
	r := 100 * 24 * time.Hour
	assert.Equal(t, lcNow.Add(r), extendTarget(lcNow, r, time.Time{}))
	assert.Equal(t, lcDays(30), extendTarget(lcNow, r, lcDays(30)))
	assert.Equal(t, lcNow.Add(r), extendTarget(lcNow, r, lcDays(200)))
	assert.Equal(t, lcNow.Add(r), extendTarget(lcNow, r, lcDays(-5)))
}

func TestSponsorLoop(t *testing.T) {
	m := map[string]string{"b": "a", "c": "b"}
	assert.True(t, sponsorLoop(m, "a", "a"))
	assert.True(t, sponsorLoop(m, "a", "b"))
	assert.True(t, sponsorLoop(m, "a", "c"))
	assert.False(t, sponsorLoop(m, "c", "a"))
	assert.False(t, sponsorLoop(m, "d", "c"))
	assert.False(t, sponsorLoop(map[string]string{"x": "y", "y": "x"}, "z", "x"))
}
