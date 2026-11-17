package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"
)

const (
	syncRunKey = "sync-run"
	// longer than any run: it only frees the lock of a replica that died
	// mid-run
	syncRunTTL   = time.Hour
	syncHeldKey  = "sync-held"
	syncLastKey  = "sync-last-run"
	syncSampleN  = 20
	syncAuditRun = "AUDIT sync run"
)

type syncRunResult struct {
	At      time.Time
	By      string
	DryRun  bool
	Plan    syncPlan
	Applied map[string]int // kind → count
	Errors  []string
	Held    bool
	// SkipReasons are the fix texts of Plan.Skipped
	SkipReasons []string
	// HeldCount is the number of disables and deletes the brake held; a
	// stored result keeps only the first rows of its plan.
	HeldCount int
	// HeldDisable and HeldDelete split HeldCount by kind
	HeldDisable, HeldDelete int
}

// StartSync runs the directory sync every sync.interval for the lifetime of
// the process; without an interval only `mokey sync` and admin Apply run it.
func (r *Router) StartSync() {
	if !r.sync.on() || r.sync.Interval == 0 {
		return
	}
	slog.Info("Directory sync enabled", "interval", r.sync.Interval)
	startLoop(func() {
		for {
			if r.lock.lease("sync", r.sync.Interval) {
				if _, ran, err := r.syncRunLocked(context.Background(), time.Now(), "", false); err != nil {
					slog.Error("Directory sync run failed", "err", err)
				} else if !ran {
					slog.Info("Directory sync skipped, another run is in progress")
				}
			}
			time.Sleep(r.sync.Interval)
		}
	})
}

// syncRunLocked runs syncRun unless another run, on any replica, holds
// syncRunKey; ran is false then.
func (r *Router) syncRunLocked(ctx context.Context, now time.Time, by string, dryRun bool) (*syncRunResult, bool, error) {
	release, ok, err := r.lock.claim(syncRunKey, syncRunTTL)
	if !ok {
		return nil, false, err
	}
	defer release()
	res, err := r.syncRun(ctx, now, by, dryRun)
	return res, true, err
}

func (r *Router) syncGoogle() (syncSource, error) {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	if r.syncSrc == nil {
		// Background: the token source keeps the context for later refreshes
		src, err := newGoogleSource(context.Background(), r.sync.Google, slices.Sorted(maps.Keys(r.sync.GroupMapping)))
		if err != nil {
			return nil, err
		}
		r.syncSrc = src
	}
	return r.syncSrc, nil
}

// syncCaps bound an admin Apply to the disables and deletes the admin saw.
type syncCaps struct{ Disable, Delete int }

var errSyncPlanGrew = errors.New("the plan changed since the admin opened it: more locks or deletes than approved, nothing applied")

// syncRun plans and applies one pass; the caller holds syncRunKey. by "" is
// the schedule or `mokey sync`: the brake holds disables and deletes. An
// admin uid applies the whole plan in their name. A dry run returns the
// plan and writes nothing.
func (r *Router) syncRun(ctx context.Context, now time.Time, by string, dryRun bool) (*syncRunResult, error) {
	return r.syncRunCapped(ctx, now, by, dryRun, nil)
}

// syncRunCapped is syncRun that, with caps, applies nothing when the plan
// disables or deletes more than caps allow.
func (r *Router) syncRunCapped(ctx context.Context, now time.Time, by string, dryRun bool, caps *syncCaps) (*syncRunResult, error) {
	res := &syncRunResult{At: now, By: by, DryRun: dryRun, Applied: map[string]int{}}
	actor := by
	if actor == "" {
		actor = "sync"
	}
	cfg := r.sync
	if by != "" {
		noBrake := *r.sync
		noBrake.MaxDisablePercent = 0
		cfg = &noBrake
	}

	in, err := r.syncRead(ctx, cfg, now)
	if err != nil {
		res.Errors = []string{err.Error()}
		if dryRun {
			slog.Error("Directory sync dry run failed", "by", actor, "err", err)
			return res, err
		}
		// AUDIT, so webhooks see the failed run; "aborted" means no changes made
		slog.Error(syncAuditRun, "by", actor, "aborted", true, "err", err)
		r.syncFinish(res)
		return res, err
	}
	plan := in.build(cfg, now)
	res.Plan, res.SkipReasons = plan, in.reasons
	if dryRun {
		return res, nil
	}
	if caps != nil && (len(plan.Disable) > caps.Disable || len(plan.Delete) > caps.Delete) {
		res.Errors = []string{errSyncPlanGrew.Error()}
		slog.Error(syncAuditRun, "by", actor, "aborted", true, "err", errSyncPlanGrew,
			"disable", len(plan.Disable), "approved_disable", caps.Disable, "delete", len(plan.Delete), "approved_delete", caps.Delete)
		if err := r.syncStoreHeld(syncHeldOf(now, plan, in.reasons)); err != nil {
			res.Errors = append(res.Errors, err.Error())
		}
		r.syncFinish(res)
		return res, errSyncPlanGrew
	}

	var held *syncRunResult
	if plan.Braked {
		noBrake := *cfg
		noBrake.MaxDisablePercent = 0
		held = syncHeldOf(now, in.build(&noBrake, now), in.reasons)
		held.By = by
		res.Held = true
		res.HeldDisable, res.HeldDelete, res.HeldCount = held.HeldDisable, held.HeldDelete, held.HeldCount
		slog.Warn("Directory sync disables and deletes held: more than sync.max_disable_percent of managed accounts, apply them from the admin Sync page",
			"held", res.HeldCount, "max_disable_percent", cfg.MaxDisablePercent)
	}
	if err := r.syncStoreHeld(held); err != nil {
		res.Errors = append(res.Errors, err.Error())
	}

	r.syncApply(ctx, res, in.ipa, cfg, now, actor)
	r.syncFinish(res)
	return res, nil
}

// syncHeldOf is the stored held result for full, a plan without the brake.
func syncHeldOf(now time.Time, full syncPlan, reasons []string) *syncRunResult {
	return &syncRunResult{At: now, Held: true, HeldCount: len(full.Disable) + len(full.Delete),
		HeldDisable: len(full.Disable), HeldDelete: len(full.Delete), Plan: full.sample(syncSampleN), SkipReasons: reasons}
}

type syncInputs struct {
	users   []syncUser
	skipped []string
	reasons []string
	ipa     map[string]syncIPAUser
}

func (in syncInputs) build(cfg *syncConfig, now time.Time) syncPlan {
	return syncBuild(in.users, in.skipped, in.ipa, cfg, now)
}

// syncRead reads Google and FreeIPA; any read error aborts the run.
func (r *Router) syncRead(ctx context.Context, cfg *syncConfig, now time.Time) (syncInputs, error) {
	src, err := r.syncGoogle()
	if err != nil {
		return syncInputs{}, fmt.Errorf("google: %w", err)
	}
	raw, err := src.Users(ctx)
	if err != nil {
		return syncInputs{}, fmt.Errorf("google: %w", err)
	}
	in := syncInputs{}
	var errs []error
	in.users, in.skipped, errs = syncResolve(raw, cfg.Username, cfg.ExcludeUsers, cfg.MaxUsernameLength)
	for _, e := range errs {
		slog.Warn("Directory sync skipped a Google user", "err", e)
		in.reasons = append(in.reasons, e.Error())
	}
	uids := make([]string, len(in.users))
	for i, u := range in.users {
		uids[i] = u.UID
	}
	if in.ipa, err = r.syncLoadIPA(ctx, cfg, uids, now); err != nil {
		return syncInputs{}, fmt.Errorf("freeipa: %w", err)
	}
	return in, nil
}

func (r *Router) syncStoreHeld(held *syncRunResult) error {
	if held == nil {
		if err := r.storage.Delete(syncHeldKey); err != nil {
			slog.Error("Failed to clear the held sync plan", "err", err)
			return fmt.Errorf("clear held plan: %w", err)
		}
		return nil
	}
	b, err := json.Marshal(held)
	if err == nil {
		err = r.storage.Set(syncHeldKey, b, 0)
	}
	if err != nil {
		slog.Error("Failed to store the held sync plan", "err", err)
		return fmt.Errorf("store held plan: %w", err)
	}
	return nil
}

// syncApply runs the plan step by step as google2ipa did: create, adopt,
// update, enable, groups, markers, disable, delete.
func (r *Router) syncApply(ctx context.Context, res *syncRunResult, cur map[string]syncIPAUser, cfg *syncConfig, now time.Time, by string) {
	p := res.Plan
	var bulk []any
	if p.Changes() > cfg.MaxEventsPerRun {
		bulk = []any{"bulk", true}
	}
	var mu sync.Mutex
	failed := map[string]bool{}
	ok := func(kind, uid string, err error, audit string, attrs ...any) bool {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			failed[uid] = true
			res.Errors = append(res.Errors, fmt.Sprintf("%s %s: %v", kind, uid, err))
			slog.Error("Directory sync change failed", "kind", kind, "username", uid, "by", by, "err", err)
			return false
		}
		res.Applied[kind]++
		if audit != "" {
			slog.Info(audit, append(append([]any{"username", uid, "by", by}, attrs...), bulk...)...)
		}
		return true
	}
	n := cfg.Concurrency

	syncEach(ctx, n, p.Create, func(u syncUser) {
		if !ok("create", u.UID, r.syncCreate(u, cfg), "AUDIT sync user created", "email", u.Email) {
			return
		}
		if cfg.WelcomeMail {
			if err := r.syncWelcome(u.UID, cfg.WelcomeLinkTTL); err != nil {
				// not `failed`: the account exists and still gets its groups
				mu.Lock()
				res.Errors = append(res.Errors, fmt.Sprintf("welcome mail %s: %v", u.UID, err))
				mu.Unlock()
				slog.Error("Directory sync welcome mail failed", "username", u.UID, "by", by, "err", err)
			}
		}
	})
	syncEach(ctx, n, p.Adopt, func(uid string) {
		ok("adopt", uid, r.syncGroups(uid, []string{cfg.ManagedGroup}, nil), "AUDIT sync user adopted")
	})
	syncEach(ctx, n, p.Update, func(u syncUpdate) {
		ok("update", u.UID, r.syncUpdate(u), "AUDIT sync user updated", "from", u.From.Email, "email", u.To.Email)
	})
	syncEach(ctx, n, p.Enable, func(uid string) {
		var err error
		if m := cur[uid].Marker; m != nil {
			err = r.syncEnable(uid, *m)
		} else {
			err = fmt.Errorf("no sync marker")
		}
		ok("enable", uid, err, "AUDIT sync user enabled")
	})
	groupUIDs := slices.Sorted(maps.Keys(p.AddGroups))
	for uid := range p.RemoveGroups {
		if !slices.Contains(groupUIDs, uid) {
			groupUIDs = append(groupUIDs, uid)
		}
	}
	syncEach(ctx, n, groupUIDs, func(uid string) {
		mu.Lock()
		skip := failed[uid]
		mu.Unlock()
		if skip {
			return
		}
		for _, g := range p.AddGroups[uid] {
			ok("group_add", uid, r.syncGroups(uid, []string{g}, nil), "AUDIT sync group added", "group", g)
		}
		for _, g := range p.RemoveGroups[uid] {
			ok("group_remove", uid, r.syncGroups(uid, nil, []string{g}), "AUDIT sync group removed", "group", g)
		}
	})
	syncEach(ctx, n, slices.Sorted(maps.Keys(p.NewMarkers)), func(uid string) {
		ok("marker", uid, r.syncSetMarker(uid, p.NewMarkers[uid]), "")
	})
	syncEach(ctx, n, p.ClearMarkers, func(uid string) {
		ok("marker_clear", uid, r.syncClearMarker(uid), "")
	})
	syncEach(ctx, n, p.Disable, func(uid string) {
		ok("disable", uid, r.syncDisable(uid, now, by), "AUDIT sync user disabled")
	})
	syncEach(ctx, n, p.Delete, func(uid string) {
		ok("delete", uid, r.syncDelete(uid, cfg.Preserve), "AUDIT sync user deleted", "preserve", cfg.Preserve)
	})

	if err := ctx.Err(); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("run stopped, remaining changes skipped: %v", err))
	}
	counts := []any{"by", by, "planned", p.Changes(), "held", res.Held, "held_count", res.HeldCount, "errors", len(res.Errors),
		"conflicts", len(p.Conflicts), "skipped", len(p.Skipped)}
	for _, k := range slices.Sorted(maps.Keys(res.Applied)) {
		counts = append(counts, k, res.Applied[k])
	}
	slog.Info(syncAuditRun, counts...)
}

// syncFinish records the run for the admin page and metrics.
func (r *Router) syncFinish(res *syncRunResult) {
	stored := *res
	stored.Plan = res.Plan.sample(syncSampleN)
	b, err := json.Marshal(stored)
	if err == nil {
		err = r.storage.Set(syncLastKey, b, 0)
	}
	if err != nil {
		slog.Error("Failed to store the sync run result", "err", err)
		res.Errors = append(res.Errors, fmt.Sprintf("store run result: %v", err))
	}
	if r.metrics == nil {
		return
	}
	r.metrics.syncLastRun.Set(float64(res.At.Unix()))
	if len(res.Errors) == 0 {
		r.metrics.syncLastSuccess.Set(float64(res.At.Unix()))
	}
	held := 0.0
	if res.Held {
		held = 1
	}
	r.metrics.syncHeld.Set(held)
	for k, v := range res.Applied {
		r.metrics.syncChanges.WithLabelValues(k).Add(float64(v))
	}
}

// syncEach runs fn on every item with at most n at a time, and starts no
// more once ctx is done.
func syncEach[T any](ctx context.Context, n int, items []T, fn func(T)) {
	sem := make(chan struct{}, max(n, 1))
	var wg sync.WaitGroup
	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			fn(it)
		})
	}
	wg.Wait()
}

// sample keeps the first n rows of each list, for storage.
func (p syncPlan) sample(n int) syncPlan {
	cut := func(s []string) []string { return s[:min(len(s), n)] }
	cutMap := func(m map[string][]string) map[string][]string {
		out := map[string][]string{}
		for _, k := range cut(slices.Sorted(maps.Keys(m))) {
			out[k] = m[k]
		}
		return out
	}
	out := p
	out.Create = p.Create[:min(len(p.Create), n)]
	out.Update = p.Update[:min(len(p.Update), n)]
	out.Adopt, out.Unmanaged = cut(p.Adopt), cut(p.Unmanaged)
	out.Enable, out.Disable, out.Delete = cut(p.Enable), cut(p.Disable), cut(p.Delete)
	out.ClearMarkers, out.BackInGoogle = cut(p.ClearMarkers), cut(p.BackInGoogle)
	out.Conflicts, out.Skipped = cut(p.Conflicts), cut(p.Skipped)
	out.AddGroups, out.RemoveGroups = cutMap(p.AddGroups), cutMap(p.RemoveGroups)
	out.NewMarkers = map[string]syncMarker{}
	for _, k := range cut(slices.Sorted(maps.Keys(p.NewMarkers))) {
		out.NewMarkers[k] = p.NewMarkers[k]
	}
	return out
}

// syncLastRun returns the last recorded run, or nil.
func (r *Router) syncLastRun() (*syncRunResult, error) {
	return r.syncLoadResult(syncLastKey)
}

// syncHeld returns the plan the brake last held, or nil.
func (r *Router) syncHeld() (*syncRunResult, error) {
	return r.syncLoadResult(syncHeldKey)
}

func (r *Router) syncLoadResult(key string) (*syncRunResult, error) {
	raw, err := r.storage.Get(key)
	if err != nil || raw == nil {
		return nil, err
	}
	res := &syncRunResult{}
	if err := json.Unmarshal(raw, res); err != nil {
		return nil, err
	}
	return res, nil
}
