package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSyncSource struct {
	users []syncSourceUser
	err   error
	block chan struct{} // Users waits for it to close when set
}

func (f *fakeSyncSource) Users(context.Context) ([]syncSourceUser, error) {
	if f.block != nil {
		<-f.block
	}
	return f.users, f.err
}

func googleUser(uid string) syncSourceUser {
	return syncSourceUser{Email: uid + "@example.org", GivenName: "G", FamilyName: uid, FullName: "G " + uid}
}

func syncRunRouter(t *testing.T) (*Router, *ipatest.Server, *fakeSyncSource, *bytes.Buffer) {
	t.Helper()
	r, fake, cfg := syncTargetRouter(t)
	stubCN(fake)
	cfg.Username = "local_part"
	cfg.MaxUsernameLength = 32
	cfg.Concurrency = 4
	cfg.MaxEventsPerRun = 50
	cfg.MaxDisablePercent = 20
	cfg.Disable = true
	cfg.Preserve = true
	r.sync = cfg
	r.lock = newStoreLock(r.storage)
	r.metrics = NewMetrics()
	src := &fakeSyncSource{}
	r.syncSrc = src

	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(NewAuditHandler(slog.NewTextHandler(&logs, nil), r.storage)))
	t.Cleanup(func() { slog.SetDefault(saved) })
	return r, fake, src, &logs
}

// managed adds uids as active accounts in the managed group.
func managed(fake *ipatest.Server, uids ...string) {
	for _, uid := range uids {
		fake.AddUser(uid, ipatest.User{Email: uid + "@example.org", First: "G", Last: uid, DisplayName: "G " + uid})
	}
	fake.AddGroup("google2ipa-managed", ipatest.Group{Members: uids})
}

func writeCalls(fake *ipatest.Server) []string {
	var out []string
	for _, c := range fake.Calls() {
		switch c.Method {
		case "user_add", "user_mod", "user_disable", "user_enable", "user_del", "group_add_member", "group_remove_member":
			out = append(out, c.Method)
		}
	}
	return out
}

func locked(fake *ipatest.Server, uid string) bool {
	u, _ := fake.User(uid)
	return u.Locked
}

func TestSyncRunSourceErrorNoChanges(t *testing.T) {
	r, fake, src, _ := syncRunRouter(t)
	managed(fake, "jesse", "walt")
	src.err = errors.New("google down")

	res, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.Error(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.Errors)
	assert.Empty(t, writeCalls(fake))
	last, err := r.syncLastRun()
	require.NoError(t, err)
	require.NotNil(t, last)
	assert.Contains(t, last.Errors[0], "google down")
	sum := auditEvents(r, "sync run")
	if assert.Len(t, sum, 1) {
		assert.Equal(t, "true", sum[0].Attrs["aborted"])
	}
}

func TestSyncRunIPAErrorNoChanges(t *testing.T) {
	r, fake, src, _ := syncRunRouter(t)
	src.users = []syncSourceUser{googleUser("jesse")}
	r.sync.DefaultGroups = []string{"missing"}

	_, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.Error(t, err)
	assert.Empty(t, writeCalls(fake))
}

// ten managed accounts, five gone from Google, one new
func brakeSetup(t *testing.T) (*Router, *ipatest.Server) {
	r, fake, src, _ := syncRunRouter(t)
	var uids []string
	for i := range 10 {
		uids = append(uids, fmt.Sprintf("user%d", i))
	}
	managed(fake, uids...)
	fake.AddGroup("staff", ipatest.Group{Members: uids})
	for _, uid := range uids[:5] {
		src.users = append(src.users, googleUser(uid))
	}
	src.users = append(src.users, googleUser("jesse"))
	return r, fake
}

func TestSyncRunBrakeHolds(t *testing.T) {
	r, fake := brakeSetup(t)

	res, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.NoError(t, err)
	assert.True(t, res.Held)
	assert.Equal(t, 1, res.Applied["create"])
	_, ok := fake.User("jesse")
	assert.True(t, ok, "creates apply while the brake holds")
	for i := range 10 {
		assert.False(t, locked(fake, fmt.Sprintf("user%d", i)))
	}
	held, err := r.syncHeld()
	require.NoError(t, err)
	require.NotNil(t, held)
	assert.True(t, held.Held)
	assert.Equal(t, 5, held.HeldCount)
	assert.Equal(t, []string{"user5", "user6", "user7", "user8", "user9"}, held.Plan.Disable)
	assert.Equal(t, 1.0, gaugeValue(t, r.metrics.syncHeld))
}

func TestSyncRunAdminApplyLiftsBrake(t *testing.T) {
	r, fake := brakeSetup(t)
	cfg := *r.sync
	_, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.NoError(t, err)

	res, err := r.syncRun(context.Background(), time.Now(), "gus", false)
	require.NoError(t, err)
	assert.False(t, res.Held)
	assert.Equal(t, 5, res.Applied["disable"])
	for i := range 10 {
		assert.Equal(t, i >= 5, locked(fake, fmt.Sprintf("user%d", i)))
	}
	m, err := r.syncGetMarker("user5")
	require.NoError(t, err)
	assert.Equal(t, "gus", m.By)
	held, err := r.syncHeld()
	require.NoError(t, err)
	assert.Nil(t, held)
	assert.Equal(t, cfg, *r.sync, "the brake is lifted for this run only")
	dis := auditEvents(r, "sync user disabled")
	if assert.Len(t, dis, 5) {
		assert.Equal(t, "gus", dis[0].Actor)
	}
	assert.Equal(t, 0.0, gaugeValue(t, r.metrics.syncHeld))
}

func TestSyncRunDryRunChangesNothing(t *testing.T) {
	r, fake := brakeSetup(t)
	r.sync.MaxDisablePercent = 0

	res, err := r.syncRun(context.Background(), time.Now(), "", true)
	require.NoError(t, err)
	assert.True(t, res.DryRun)
	assert.Len(t, res.Plan.Create, 1)
	assert.Len(t, res.Plan.Disable, 5)
	assert.Empty(t, res.Applied)
	assert.Empty(t, writeCalls(fake))
	for _, key := range []string{syncLastKey, syncHeldKey, syncMarkerPrefix + "user5"} {
		v, err := r.storage.Get(key)
		require.NoError(t, err)
		assert.Nil(t, v, key)
	}
	assert.Empty(t, auditEvents(r, "sync run"))
}

func TestSyncRunClaimExclusive(t *testing.T) {
	r, _, src, _ := syncRunRouter(t)
	src.block = make(chan struct{})
	done := make(chan bool)
	go func() {
		_, ran, err := r.syncRunLocked(context.Background(), time.Now(), "", false)
		assert.NoError(t, err)
		done <- ran
	}()
	require.Eventually(t, func() bool {
		v, _ := r.storage.Get(syncRunKey)
		return v != nil
	}, 5*time.Second, 10*time.Millisecond)

	res, ran, err := r.syncRunLocked(context.Background(), time.Now(), "gus", false)
	require.NoError(t, err)
	assert.False(t, ran)
	assert.Nil(t, res)

	close(src.block)
	assert.True(t, <-done)
	_, ran, err = r.syncRunLocked(context.Background(), time.Now(), "gus", false)
	require.NoError(t, err)
	assert.True(t, ran, "the claim is released after a run")
}

func TestSyncRunBulkEvents(t *testing.T) {
	r, _, src, _ := syncRunRouter(t)
	r.sync.DefaultGroups = nil
	for i := range 51 {
		src.users = append(src.users, googleUser(fmt.Sprintf("user%02d", i)))
	}

	res, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.NoError(t, err)
	assert.Empty(t, res.Errors)
	assert.Equal(t, 51, res.Applied["create"])
	created := auditEvents(r, "sync user created")
	require.Len(t, created, 51)
	for _, e := range created {
		assert.Equal(t, "true", e.Attrs["bulk"])
		assert.Equal(t, "sync", e.Actor)
	}
	sum := auditEvents(r, "sync run")
	if assert.Len(t, sum, 1) {
		assert.Empty(t, sum[0].Attrs["bulk"])
		assert.Equal(t, "51", sum[0].Attrs["create"])
	}
}

func TestSyncRunSmallRunNotBulk(t *testing.T) {
	r, fake, src, _ := syncRunRouter(t)
	src.users = []syncSourceUser{googleUser("jesse")}

	res, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.NoError(t, err)
	assert.Empty(t, res.Errors)
	assert.Equal(t, map[string]int{"create": 1, "group_add": 1}, res.Applied)
	staff, _ := fake.Group("staff")
	assert.Contains(t, staff.Members, "jesse")
	created := auditEvents(r, "sync user created")
	if assert.Len(t, created, 1) {
		assert.Empty(t, created[0].Attrs["bulk"])
	}
	assert.Len(t, auditEvents(r, "sync group added"), 1)
	assert.Greater(t, gaugeValue(t, r.metrics.syncLastSuccess), 0.0)
}

func TestSyncRunGroupsSkipFailedCreate(t *testing.T) {
	r, fake, src, _ := syncRunRouter(t)
	src.users = []syncSourceUser{googleUser("jesse")}
	fake.Handle("user_add", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: 4002, Message: "refused"}
	})

	res, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.NoError(t, err)
	assert.Len(t, res.Errors, 1)
	assert.Empty(t, res.Applied)
	assert.False(t, slices.Contains(writeCalls(fake), "group_add_member"))
}

// keyFailingSetStorage refuses writes of one key.
type keyFailingSetStorage struct {
	fiber.Storage
	key string
}

func (s *keyFailingSetStorage) Set(key string, val []byte, exp time.Duration) error {
	if key == s.key {
		return errors.New("storage backend down")
	}
	return s.Storage.Set(key, val, exp)
}

func TestSyncRunLastRunSaveFailure(t *testing.T) {
	r, fake, src, _ := syncRunRouter(t)
	managed(fake, "jesse", "walt")
	src.users = []syncSourceUser{googleUser("walt")}
	r.storage = &keyFailingSetStorage{r.storage, syncLastKey}

	res, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.NoError(t, err)
	assert.True(t, locked(fake, "jesse"))
	assert.Equal(t, 1, res.Applied["disable"])
	if assert.Len(t, res.Errors, 1) {
		assert.Contains(t, res.Errors[0], "storage backend down")
	}
}

func TestSyncRunFoundMarkerWriteFailure(t *testing.T) {
	r, fake, src, _ := syncRunRouter(t)
	managed(fake, "jesse", "walt")
	fake.UpdateUser("jesse", func(u *ipatest.User) { u.Locked = true })
	src.users = []syncSourceUser{googleUser("walt")}
	r.storage = &keyFailingSetStorage{r.storage, syncMarkerPrefix + "jesse"}

	res, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.NoError(t, err)
	if assert.Len(t, res.Errors, 1) {
		assert.Contains(t, res.Errors[0], "jesse")
	}
	assert.Greater(t, gaugeValue(t, r.metrics.syncLastRun), 0.0)
}

func TestStartSyncOnlyWhenScheduled(t *testing.T) {
	r := &Router{}
	r.StartSync() // sync off: returns at once
	r.sync = &syncConfig{}
	r.StartSync() // no interval: only mokey sync and admin Apply
}

func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, g.Write(&m))
	return m.GetGauge().GetValue()
}

func TestSyncRunMarkerWriteFailure(t *testing.T) {
	r, fake, src, _ := syncRunRouter(t)
	r.sync.MaxDisablePercent = 0
	managed(fake, "jesse", "walt", "skyler")
	src.users = []syncSourceUser{googleUser("skyler")}
	r.storage = &keyFailingSetStorage{r.storage, syncMarkerPrefix + "jesse"}

	res, err := r.syncRun(context.Background(), time.Now(), "", false)
	require.NoError(t, err)
	assert.False(t, locked(fake, "jesse"), "no lock without a marker")
	assert.True(t, locked(fake, "walt"), "the run continues")
	assert.Equal(t, 1, res.Applied["disable"])
	if assert.Len(t, res.Errors, 1) {
		assert.Contains(t, res.Errors[0], "disable jesse")
	}
}

func TestSyncRunKeepsSkipReasons(t *testing.T) {
	r, fake := brakeSetup(t)
	src := r.syncSrc.(*fakeSyncSource)
	src.users = append(src.users, syncSourceUser{Email: "Bad User@example.org", GivenName: "Bad", FamilyName: "User"})

	res, err := r.syncRun(context.Background(), time.Now(), "", true)
	require.NoError(t, err)
	require.Len(t, res.SkipReasons, 1)
	assert.Contains(t, res.SkipReasons[0], "not a valid FreeIPA uid")
	assert.Equal(t, []string{"bad user"}, res.Plan.Skipped)

	res, err = r.syncRun(context.Background(), time.Now(), "", false)
	require.NoError(t, err)
	assert.True(t, res.Held)
	_, ok := fake.User("bad user")
	assert.False(t, ok)
	for _, load := range []func() (*syncRunResult, error){r.syncLastRun, r.syncHeld} {
		stored, err := load()
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Equal(t, res.SkipReasons, stored.SkipReasons)
	}
}
