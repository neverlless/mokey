package server

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lcFakeUser struct {
	sponsor, email string
	expires        time.Time
	disabled       bool
}

// lcDir stands in for the FreeIPA attributes ipatest does not keep
// (manager, krbprincipalexpiration).
type lcDir struct {
	mu        sync.Mutex
	users     map[string]*lcFakeUser
	refuse    map[string]bool
	truncated bool
	mods      int
	fake      *ipatest.Server
}

func newLifecycleApp(t *testing.T, cfg *lifecycleConfig) (*Router, *lcDir, *bytes.Buffer) {
	t.Helper()
	_, router, fake := newTestApp(t)
	router.lifecycle = cfg
	dir := &lcDir{users: map[string]*lcFakeUser{}, refuse: map[string]bool{}, fake: fake}

	fake.Handle("user_find", func(c ipatest.Call) (any, *ipa.IpaError) {
		assert.Equal(t, true, c.Options["all"])
		dir.mu.Lock()
		defer dir.mu.Unlock()
		var out []map[string]any
		for uid, u := range dir.users {
			e := map[string]any{"uid": []string{uid}, "givenname": []string{strings.ToUpper(uid[:1]) + uid[1:]}, "nsaccountlock": u.disabled}
			if u.email != "" {
				e["mail"] = []string{u.email}
			}
			if u.sponsor != "" {
				e["manager"] = []string{"uid=" + u.sponsor + ",cn=users,cn=accounts,dc=test,dc=local"}
			}
			if !u.expires.IsZero() {
				e["krbprincipalexpiration"] = []any{map[string]string{"__datetime__": u.expires.UTC().Format(ipa.IpaDatetimeFormat)}}
			}
			out = append(out, e)
		}
		return map[string]any{"result": out, "count": len(out), "truncated": dir.truncated}, nil
	})
	fake.Handle("user_mod", func(c ipatest.Call) (any, *ipa.IpaError) {
		dir.mu.Lock()
		defer dir.mu.Unlock()
		uid := c.Args[0]
		if dir.refuse[uid] {
			return nil, &ipa.IpaError{Code: 2100, Message: "Insufficient access: Insufficient 'write' privilege to the 'krbPrincipalExpiration' attribute"}
		}
		dir.mods++
		v, _ := c.Options["krbprincipalexpiration"].(map[string]any)
		dir.users[uid].expires, _ = time.Parse(ipa.IpaDatetimeFormat, fmt.Sprint(v["__datetime__"]))
		return map[string]any{"result": map[string]any{}}, nil
	})

	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(NewAuditHandler(slog.NewTextHandler(&logs, nil), router.storage)))
	t.Cleanup(func() { slog.SetDefault(saved) })
	return router, dir, &logs
}

func (d *lcDir) add(uid string, u lcFakeUser) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[uid] = &u
}

func (d *lcDir) modCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mods
}

func auditEvents(router *Router, msg string) []AuditEvent {
	var out []AuditEvent
	for _, e := range auditRecent(router.storage, auditRingSize) {
		if e.Message == msg {
			out = append(out, e)
		}
	}
	return out
}

func assignCfg() *lifecycleConfig {
	return &lifecycleConfig{Renewal: 365 * 24 * time.Hour, AssignMissing: true, MaxChanges: 50}
}

func TestLifecycleRunAppliesSmallPlan(t *testing.T) {
	assert := assert.New(t)
	router, dir, _ := newLifecycleApp(t, assignCfg())
	dir.add("walter", lcFakeUser{})
	for _, uid := range []string{"jesse", "skinny", "badger"} {
		dir.add(uid, lcFakeUser{sponsor: "walter"})
	}
	now := time.Now()

	applied, held, err := router.lifecycleRun(now, "")
	require.NoError(t, err)
	assert.Equal(3, applied)
	assert.Nil(held)
	assert.Equal(3, dir.modCount())
	assert.WithinDuration(now.Add(365*24*time.Hour), dir.users["jesse"].expires, time.Second)

	set := auditEvents(router, "lifecycle expiry set")
	if assert.Len(set, 3) {
		assert.Equal("system", set[0].Attrs["by"])
		assert.Equal("system", set[0].Actor)
		assert.Empty(set[0].Attrs["bulk"])
	}
	sum := auditEvents(router, "lifecycle run applied")
	if assert.Len(sum, 1) {
		assert.Equal("3", sum[0].Attrs["count"])
		assert.Equal("0", sum[0].Attrs["failed"])
	}
}

func TestLifecycleBrakeHoldsAndForceApplies(t *testing.T) {
	assert := assert.New(t)
	router, dir, logs := newLifecycleApp(t, assignCfg())
	dir.add("walter", lcFakeUser{})
	for i := range 60 {
		dir.add(fmt.Sprintf("student%02d", i), lcFakeUser{sponsor: "walter"})
	}
	now := time.Now()

	applied, held, err := router.lifecycleRun(now, "")
	require.NoError(t, err)
	assert.Equal(0, applied)
	assert.Equal(0, dir.modCount())
	if assert.NotNil(held) {
		assert.Equal(60, held.Count)
		assert.Len(held.Sample, 20)
	}
	assert.Contains(logs.String(), "level=WARN")
	stored, err := router.lifecycleHeld()
	require.NoError(t, err)
	if assert.NotNil(stored) {
		assert.Equal(60, stored.Count)
		assert.Len(stored.Sample, 20)
		assert.Equal("student00", stored.Sample[0].UID)
	}
	assert.Empty(auditEvents(router, "lifecycle expiry set"))

	applied, held, err = router.lifecycleRun(now, "gus")
	require.NoError(t, err)
	assert.Equal(60, applied)
	assert.Nil(held)
	assert.Equal(60, dir.modCount())
	stored, err = router.lifecycleHeld()
	require.NoError(t, err)
	assert.Nil(stored)
	set := auditEvents(router, "lifecycle expiry set")
	if assert.Len(set, 60) {
		assert.Equal("true", set[0].Attrs["bulk"])
		assert.Equal("gus", set[0].Actor)
	}
	sum := auditEvents(router, "lifecycle run applied")
	if assert.Len(sum, 1) {
		assert.Equal("gus", sum[0].Actor)
		assert.Equal("60", sum[0].Attrs["count"])
	}

	applied, _, err = router.lifecycleRun(now, "gus")
	require.NoError(t, err)
	assert.Equal(0, applied)
	assert.Equal(60, dir.modCount())
}

func TestWebhooksSkipBulkEvents(t *testing.T) {
	target := &webhookTarget{queue: make(chan AuditEvent, 4)}
	w := &webhooks{targets: []*webhookTarget{target}}
	w.send(AuditEvent{Message: "lifecycle expiry set", Attrs: map[string]string{"bulk": "true"}})
	w.send(AuditEvent{Message: "lifecycle run applied"})
	assert.Len(t, target.queue, 1)
}

func TestLifecycleReminders(t *testing.T) {
	assert := assert.New(t)
	router, dir, _ := newLifecycleApp(t, &lifecycleConfig{Reminders: []int{30, 7, 1}, MaxChanges: 50})
	sink := newFakeSMTP(t)
	now := time.Now()
	dir.add("walter", lcFakeUser{email: "walter@example.test"})
	dir.add("jesse", lcFakeUser{sponsor: "walter", email: "jesse@example.test", expires: now.Add(7*24*time.Hour - time.Hour)})
	dir.add("skinny", lcFakeUser{email: "skinny@example.test", expires: now.Add(60 * 24 * time.Hour)})

	_, _, err := router.lifecycleRun(now, "")
	require.NoError(t, err)
	msgs := sink.all()
	if assert.Len(msgs, 2) {
		joined := strings.Join(msgs, "\n")
		assert.Contains(joined, T("email_template.account_expiring_subject"))
		assert.Contains(joined, T("email_template.sponsored_expiring_subject")+"jesse")
		assert.Contains(joined, "jesse@example.test")
		assert.Contains(joined, "walter@example.test")
	}

	_, _, err = router.lifecycleRun(now.Add(time.Hour), "")
	require.NoError(t, err)
	assert.Len(sink.all(), 2)

	dir.users["jesse"].expires = now.Add(6 * 24 * time.Hour)
	_, _, err = router.lifecycleRun(now.Add(2*time.Hour), "")
	require.NoError(t, err)
	assert.Len(sink.all(), 4)
	assert.Equal(0, dir.modCount())
}

func TestLifecycleTruncatedSkipsChangesButReminds(t *testing.T) {
	assert := assert.New(t)
	cfg := assignCfg()
	cfg.Reminders = []int{7}
	router, dir, logs := newLifecycleApp(t, cfg)
	sink := newFakeSMTP(t)
	now := time.Now()
	dir.truncated = true
	dir.add("walter", lcFakeUser{})
	dir.add("jesse", lcFakeUser{sponsor: "walter"})
	dir.add("skinny", lcFakeUser{email: "skinny@example.test", expires: now.Add(24 * time.Hour)})

	applied, held, err := router.lifecycleRun(now, "")
	require.NoError(t, err)
	assert.Equal(0, applied)
	assert.Nil(held)
	assert.Equal(0, dir.modCount())
	assert.Equal(1, sink.count())
	assert.Contains(logs.String(), "level=WARN")
}

func TestLifecycleLeaseOneReplica(t *testing.T) {
	router, dir, _ := newLifecycleApp(t, assignCfg())
	dir.add("walter", lcFakeUser{})
	dir.add("jesse", lcFakeUser{sponsor: "walter"})
	now := time.Now()

	router.lifecycleSweep(now)
	// a second replica: own lock, same storage
	router.lock = newStoreLock(router.storage)
	dir.users["jesse"].expires = time.Time{}
	router.lifecycleSweep(now)

	assert.Equal(t, 1, dir.modCount())
}

func TestStartLifecycleOnlyWhenOn(t *testing.T) {
	router, _, _ := newLifecycleApp(t, nil)
	started := 0
	orig := startLoop
	startLoop = func(func()) { started++ }
	t.Cleanup(func() { startLoop = orig })

	router.StartLifecycle()
	assert.Equal(t, 0, started)

	router.lifecycle = assignCfg()
	router.StartLifecycle()
	assert.Equal(t, 1, started)
}

func TestLifecycleRefusedWriteContinues(t *testing.T) {
	assert := assert.New(t)
	router, dir, logs := newLifecycleApp(t, assignCfg())
	dir.add("walter", lcFakeUser{})
	for _, uid := range []string{"jesse", "skinny", "badger"} {
		dir.add(uid, lcFakeUser{sponsor: "walter"})
	}
	dir.refuse["jesse"] = true

	applied, _, err := router.lifecycleRun(time.Now(), "")
	require.NoError(t, err)
	assert.Equal(2, applied)
	assert.Equal(2, dir.modCount())
	assert.Contains(logs.String(), "level=ERROR")
	assert.Contains(logs.String(), "Mokey Modify Principal Expiration")
	sum := auditEvents(router, "lifecycle run applied")
	if assert.Len(sum, 1) {
		assert.Equal("2", sum[0].Attrs["count"])
		assert.Equal("1", sum[0].Attrs["failed"])
	}
}

func TestApplyExpiryExtendedMailsUser(t *testing.T) {
	assert := assert.New(t)
	router, dir, _ := newLifecycleApp(t, assignCfg())
	sink := newFakeSMTP(t)
	dir.add("jesse", lcFakeUser{sponsor: "walter"})
	dir.fake.AddUser("jesse", ipatest.User{Email: "jesse@example.test", First: "Jesse"})
	to := time.Now().Add(30 * 24 * time.Hour)

	require.NoError(t, router.applyExpiry("jesse", to, "walter", lcAuditExtended))
	ext := auditEvents(router, "lifecycle expiry extended")
	if assert.Len(ext, 1) {
		assert.Equal("walter", ext[0].Attrs["by"])
		assert.Equal("jesse", ext[0].Username)
	}
	msgs := sink.all()
	if assert.Len(msgs, 1) {
		assert.Contains(msgs[0], T("email_template.account_extended_subject"))
	}
}

func TestLifecycleForcedRunSendsNoReminders(t *testing.T) {
	cfg := assignCfg()
	cfg.Reminders = []int{7}
	router, dir, _ := newLifecycleApp(t, cfg)
	sink := newFakeSMTP(t)
	dir.add("skinny", lcFakeUser{email: "skinny@example.test", expires: time.Now().Add(24 * time.Hour)})

	_, _, err := router.lifecycleRun(time.Now(), "gus")
	require.NoError(t, err)
	assert.Equal(t, 0, sink.count())
}

func TestLifecycleReminderWithoutUserMailStillMailsSponsor(t *testing.T) {
	assert := assert.New(t)
	router, dir, _ := newLifecycleApp(t, &lifecycleConfig{Reminders: []int{7}, MaxChanges: 50})
	sink := newFakeSMTP(t)
	now := time.Now()
	dir.add("walter", lcFakeUser{email: "walter@example.test"})
	dir.add("jesse", lcFakeUser{sponsor: "walter", expires: now.Add(24 * time.Hour)})

	_, _, err := router.lifecycleRun(now, "")
	require.NoError(t, err)
	msgs := sink.all()
	if assert.Len(msgs, 1) {
		assert.Contains(msgs[0], T("email_template.sponsored_expiring_subject")+"jesse")
	}
	_, _, err = router.lifecycleRun(now, "")
	require.NoError(t, err)
	assert.Equal(1, sink.count())
}

func TestLifecycleMarkerReadErrorSkipsReminder(t *testing.T) {
	router, dir, logs := newLifecycleApp(t, &lifecycleConfig{Reminders: []int{7}, MaxChanges: 50})
	sink := newFakeSMTP(t)
	dir.add("skinny", lcFakeUser{email: "skinny@example.test", expires: time.Now().Add(24 * time.Hour)})
	router.storage = &failingStorage{router.storage}

	_, _, err := router.lifecycleRun(time.Now(), "")
	require.NoError(t, err)
	assert.Equal(t, 0, sink.count())
	assert.Contains(t, logs.String(), "reminder marker")
}

func TestLifecycleOtherWriteErrorDoesNotNamePermission(t *testing.T) {
	router, dir, logs := newLifecycleApp(t, assignCfg())
	dir.add("walter", lcFakeUser{})
	dir.add("jesse", lcFakeUser{sponsor: "walter"})
	dir.fake.Handle("user_mod", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: 4001, Message: "jesse: user not found"}
	})

	applied, _, err := router.lifecycleRun(time.Now(), "")
	require.NoError(t, err)
	assert.Equal(t, 0, applied)
	assert.Contains(t, logs.String(), "level=ERROR")
	assert.NotContains(t, logs.String(), "Mokey Modify Principal Expiration")
}

func TestLifecycleRunOffDoesNothing(t *testing.T) {
	router, dir, _ := newLifecycleApp(t, nil)
	calls := len(dir.fake.Calls())

	applied, held, err := router.lifecycleRun(time.Now(), "gus")
	require.NoError(t, err)
	assert.Equal(t, 0, applied)
	assert.Nil(t, held)
	assert.Len(t, dir.fake.Calls(), calls)
}

func TestLifecycleForcedRunTruncatedErrors(t *testing.T) {
	router, dir, _ := newLifecycleApp(t, assignCfg())
	dir.truncated = true
	dir.add("walter", lcFakeUser{})
	dir.add("jesse", lcFakeUser{sponsor: "walter"})

	applied, _, err := router.lifecycleRun(time.Now(), "gus")
	assert.ErrorIs(t, err, errLifecycleTruncated)
	assert.Equal(t, 0, applied)
	assert.Equal(t, 0, dir.modCount())
}

func TestLifecycleFailedSponsorOnlyReminderRetries(t *testing.T) {
	router, dir, _ := newLifecycleApp(t, &lifecycleConfig{Reminders: []int{7}, MaxChanges: 50})
	now := time.Now()
	dir.add("walter", lcFakeUser{email: "walter@example.test"})
	dir.add("jesse", lcFakeUser{sponsor: "walter", expires: now.Add(24 * time.Hour)})

	// nothing listens on the default SMTP port: the sponsor mail fails
	_, _, err := router.lifecycleRun(now, "")
	require.NoError(t, err)

	sink := newFakeSMTP(t)
	_, _, err = router.lifecycleRun(now, "")
	require.NoError(t, err)
	assert.Equal(t, 1, sink.count())
}
