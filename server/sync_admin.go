package server

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

const (
	syncLegacyKey = "sync-legacy-imported"
	// the candidate count the Decisions tab last listed, for the other tabs
	syncLegacyCountKey = "sync-legacy-candidates"
)

type syncRow struct{ UID, Change, Why string }

type syncTable struct {
	Rows []syncRow
	More string
}

type syncTab struct{ Key, Label string }

type syncCount struct {
	Label string
	N     int
}

type syncDecision struct {
	UID, Text string
	People    bool // link to the account on the People page
}

type syncSetting struct {
	Label, Value string
	On           bool
}

// syncKinds orders the per-kind counts of the Last run tab; marker writes
// are bookkeeping and stay out.
var syncKinds = []string{"create", "adopt", "update", "enable", "group_add", "group_remove", "disable", "delete"}

func syncPlanCounts(p syncPlan) map[string]int {
	n := map[string]int{
		"create": len(p.Create), "adopt": len(p.Adopt), "update": len(p.Update), "enable": len(p.Enable),
		"disable": len(p.Disable), "delete": len(p.Delete),
	}
	for _, gs := range p.AddGroups {
		n["group_add"] += len(gs)
	}
	for _, gs := range p.RemoveGroups {
		n["group_remove"] += len(gs)
	}
	return n
}

// syncHeldTable lists the disables and deletes of a plan, at most
// syncSampleN of total; nil when there are none.
func syncHeldTable(lang string, p syncPlan, total int, deleteAfter time.Duration) *syncTable {
	var rows []syncRow
	for _, uid := range p.Disable {
		rows = append(rows, syncRow{uid, TL(lang, "sync.admin_change_lock"), TL(lang, "sync.admin_why_gone")})
	}
	for _, uid := range p.Delete {
		rows = append(rows, syncRow{uid, TL(lang, "sync.admin_change_delete"),
			fmt.Sprintf(TL(lang, "sync.admin_why_locked_for"), formatDuration(lang, deleteAfter))})
	}
	if total == 0 {
		return nil
	}
	t := &syncTable{Rows: rows[:min(len(rows), syncSampleN)]}
	if more := total - len(t.Rows); more > 0 {
		t.More = fmt.Sprintf(TL(lang, "admin.lifecycle_more"), more)
	}
	return t
}

// syncLegacyCandidates lists accounts a google2ipa run locked: managed,
// locked, past krbPrincipalExpiration, and no marker other than "found".
func (r *Router) syncLegacyCandidates(ctx context.Context, now time.Time) ([]string, error) {
	cur, err := r.syncLoadIPA(ctx, r.sync, nil, now)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, uid := range slices.Sorted(maps.Keys(cur)) {
		u := cur[uid]
		if u.Managed && u.Locked && u.Expired && (u.Marker == nil || u.Marker.Kind == syncMarkerFound) {
			out = append(out, uid)
		}
	}
	return out, nil
}

// syncLegacyPending is true while the one-time google2ipa import is on and not done.
func (r *Router) syncLegacyPending() (bool, error) {
	if !r.sync.ImportLegacyLocks {
		return false, nil
	}
	done, err := r.storage.Get(syncLegacyKey)
	return done == nil, err
}

// syncStatusVars fills the admin Sync page. vars may already carry a dry
// run (sy_run), a fresh plan (sy_fresh) or alerts from a POST.
func (r *Router) syncStatusVars(c fiber.Ctx, vars fiber.Map, tab string) {
	lang := requestLanguage(c)
	cfg := r.sync
	now := time.Now()
	vars["user"] = r.user(c)

	scope := strings.Join(append(slices.Clone(cfg.Google.Domains), cfg.Google.OrgUnits...), ", ")
	vars["sy_scope"] = scope
	vars["sy_managed"] = cfg.ManagedGroup
	vars["sy_mapped"] = fmt.Sprintf(TL(lang, "sync.admin_mapped"), len(cfg.mappedGroups()))

	last, err := r.syncLastRun()
	if err != nil {
		slog.Error("Failed to read the last sync run", "err", err)
		vars["sy_error"] = TL(lang, "account.fatal_system_error")
	}
	held, err := r.syncHeld()
	if err != nil {
		slog.Error("Failed to read the held sync plan", "err", err)
		vars["sy_error"] = TL(lang, "account.fatal_system_error")
	}

	running, err := r.storage.Get(syncRunKey)
	if err != nil {
		slog.Error("Failed to read the sync run lock", "err", err)
		vars["sy_error"] = TL(lang, "account.fatal_system_error")
	}
	vars["sy_running"] = running != nil
	switch {
	case running != nil:
		vars["sy_state"], vars["sy_state_class"] = TL(lang, "sync.admin_running"), "is-muted"
	case last == nil:
		vars["sy_state"], vars["sy_state_class"] = TL(lang, "sync.admin_never"), "is-muted"
	case len(last.Errors) > 0:
		vars["sy_state"], vars["sy_state_class"] = TL(lang, "sync.admin_failed"), "is-danger"
	case held != nil:
		vars["sy_state"], vars["sy_state_class"] = TL(lang, "sync.admin_held"), "is-warn"
	default:
		vars["sy_state"], vars["sy_state_class"] = TL(lang, "sync.admin_ok"), "is-ok"
	}
	var when []string
	if last != nil {
		when = append(when, fmt.Sprintf(TL(lang, "sync.admin_last_run"), timeAgo(lang, last.At)))
	}
	switch {
	case cfg.Interval == 0:
		when = append(when, TL(lang, "sync.admin_manual_only"))
	case last == nil:
		when = append(when, fmt.Sprintf(TL(lang, "sync.admin_every"), formatDuration(lang, cfg.Interval)))
	case last.At.Add(cfg.Interval).After(now):
		when = append(when, fmt.Sprintf(TL(lang, "sync.admin_next_in"), formatDuration(lang, last.At.Add(cfg.Interval).Sub(now))))
	default:
		when = append(when, TL(lang, "sync.admin_next_due"))
	}
	vars["sy_when"] = strings.Join(when, " · ")

	// held: the stored plan, or the fresh one an Apply refused
	var heldDisable, heldDelete int
	var heldPlan syncPlan
	if held != nil {
		heldDisable, heldDelete, heldPlan = held.HeldDisable, held.HeldDelete, held.Plan
	}
	if fresh, ok := vars["sy_fresh"].(*syncRunResult); ok {
		heldDisable, heldDelete, heldPlan = len(fresh.Plan.Disable), len(fresh.Plan.Delete), fresh.Plan
	}
	heldCount := heldDisable + heldDelete
	if heldCount > 0 {
		vars["sy_held_table"] = syncHeldTable(lang, heldPlan, heldCount, cfg.DeleteAfter)
		vars["sy_brake"] = fmt.Sprintf(TL(lang, "sync.admin_brake"), formatUnit(lang, "account", heldCount), cfg.MaxDisablePercent)
		vars["sy_apply"] = fmt.Sprintf(TL(lang, "sync.admin_apply"), formatUnit(lang, "change", heldCount))
		vars["sy_expect_disable"], vars["sy_expect_delete"] = heldDisable, heldDelete
	}

	var decisions []syncDecision
	if last != nil {
		for _, text := range last.Plan.Conflicts {
			// the planner starts every conflict with "uid <uid> "
			uid, _, _ := strings.Cut(strings.TrimPrefix(text, "uid "), " ")
			decisions = append(decisions, syncDecision{UID: uid, Text: text})
		}
		// SkipReasons and Plan.Skipped come from syncResolve in the same order
		for i, text := range last.SkipReasons {
			d := syncDecision{Text: text}
			if i < len(last.Plan.Skipped) {
				d.UID = last.Plan.Skipped[i]
			}
			decisions = append(decisions, d)
		}
		for _, uid := range last.Plan.BackInGoogle {
			decisions = append(decisions, syncDecision{UID: uid, Text: TL(lang, "sync.admin_back_in_google"), People: true})
		}
	}
	pending, err := r.syncLegacyPending()
	if err != nil {
		slog.Error("Failed to read the google2ipa import marker", "err", err)
		vars["sy_error"] = TL(lang, "account.fatal_system_error")
	}
	if !slices.Contains([]string{"held", "decisions", "last", "settings"}, tab) {
		switch {
		case heldCount > 0:
			tab = "held"
		case len(decisions) > 0 || pending:
			tab = "decisions"
		default:
			tab = "last"
		}
	}
	// the candidates need a full FreeIPA read: only for the tab that lists them
	decideN := len(decisions)
	switch {
	case pending && tab == "decisions":
		cands, err := r.syncLegacyCandidates(c.Context(), now)
		if err != nil {
			slog.Error("Failed to list google2ipa locks", "err", err)
			vars["sy_error"] = TL(lang, "account.fatal_system_error")
		} else if err := r.storage.Set(syncLegacyCountKey, []byte(strconv.Itoa(len(cands))), 0); err != nil {
			slog.Error("Failed to store the google2ipa lock count", "err", err)
		}
		for _, uid := range cands {
			decisions = append(decisions, syncDecision{UID: uid, Text: TL(lang, "sync.admin_legacy_lock")})
		}
		decideN = len(decisions)
		if len(cands) > 0 {
			vars["sy_import"] = fmt.Sprintf(TL(lang, "sync.admin_import"), formatUnit(lang, "account", len(cands)))
		}
	case pending:
		raw, err := r.storage.Get(syncLegacyCountKey)
		if err != nil {
			slog.Error("Failed to read the google2ipa lock count", "err", err)
			vars["sy_error"] = TL(lang, "account.fatal_system_error")
		}
		n, _ := strconv.Atoi(string(raw))
		decideN += n
	}
	vars["sy_decisions"] = decisions

	run := last
	if dry, ok := vars["sy_run"].(*syncRunResult); ok {
		run = dry
	}
	if run != nil {
		vars["sy_run_at"] = run.At.Local().Format(TL(lang, "date.layout"))
		vars["sy_run_by"] = run.By
		counts := run.Applied
		if run.DryRun {
			counts = syncPlanCounts(run.Plan)
			vars["sy_dry"] = true
			if t := syncHeldTable(lang, run.Plan, len(run.Plan.Disable)+len(run.Plan.Delete), cfg.DeleteAfter); t != nil {
				vars["sy_dry_table"] = t
			}
		}
		var rows []syncCount
		for _, k := range syncKinds {
			if counts[k] > 0 {
				rows = append(rows, syncCount{TL(lang, "sync.admin_kind_"+k), counts[k]})
			}
		}
		vars["sy_counts"] = rows
		vars["sy_errors"] = run.Errors
	}

	if last != nil {
		vars["sy_created"] = last.Applied["create"]
		vars["sy_groups"] = last.Applied["group_add"] + last.Applied["group_remove"]
	}
	vars["sy_held_n"] = heldCount
	vars["sy_decide_n"] = decideN

	vars["sy_tab"] = tab
	vars["sy_tabs"] = []syncTab{
		{"held", fmt.Sprintf("%s · %d", TL(lang, "sync.admin_tab_held"), heldCount)},
		{"decisions", fmt.Sprintf("%s · %d", TL(lang, "sync.admin_tab_decisions"), decideN)},
		{"last", TL(lang, "sync.admin_tab_last")},
		{"settings", TL(lang, "sync.admin_tab_settings")},
	}

	on, off := TL(lang, "admin.lifecycle_on"), TL(lang, "admin.lifecycle_off")
	setting := func(key string, enabled bool, value string) syncSetting {
		if value == "" {
			value = off
			if enabled {
				value = on
			}
		}
		return syncSetting{TL(lang, key), value, enabled}
	}
	onValue := func(s string) string { return fmt.Sprintf(TL(lang, "admin.lifecycle_on_value"), s) }
	var interval, deleteAfter, brake string
	if cfg.Interval > 0 {
		interval = onValue(formatDuration(lang, cfg.Interval))
	}
	if cfg.DeleteAfter > 0 {
		deleteAfter = onValue(formatDuration(lang, cfg.DeleteAfter))
	}
	if cfg.MaxDisablePercent > 0 {
		brake = onValue(strconv.Itoa(cfg.MaxDisablePercent) + "%")
	}
	vars["sy_settings"] = []syncSetting{
		setting("sync.admin_set_interval", cfg.Interval > 0, interval),
		setting("sync.admin_set_disable", cfg.Disable, ""),
		setting("sync.admin_set_delete", cfg.DeleteAfter > 0, deleteAfter),
		setting("sync.admin_set_preserve", cfg.Preserve, ""),
		setting("sync.admin_set_brake", cfg.MaxDisablePercent > 0, brake),
		setting("sync.admin_set_adopt", cfg.AdoptExisting, ""),
		setting("sync.admin_set_welcome", cfg.WelcomeMail, ""),
		setting("sync.admin_set_legacy", pending, ""),
	}
}

func (r *Router) renderSyncStatus(c fiber.Ctx, vars fiber.Map, tab string) error {
	r.syncStatusVars(c, vars, tab)
	return c.Render("admin-sync-status.html", vars)
}

func (r *Router) AdminSyncStatus(c fiber.Ctx) error {
	if !r.sync.on() {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	return r.renderSyncStatus(c, fiber.Map{}, c.Query("tab"))
}

// syncBusy answers a POST that found the run claim taken.
func (r *Router) syncBusy(c fiber.Ctx, err error) error {
	vars := fiber.Map{"sy_alert": TC(c, "sync.admin_busy")}
	if err != nil {
		slog.Error("Directory sync run not started, storage unavailable", "err", err)
		vars = fiber.Map{"sy_error": TC(c, "account.fatal_system_error")}
	}
	return r.renderSyncStatus(c, vars, "")
}

func (r *Router) AdminSyncDryRun(c fiber.Ctx) error {
	if !r.sync.on() {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	res, ran, err := r.syncRunLocked(context.Background(), time.Now(), r.username(c), true)
	if !ran {
		return r.syncBusy(c, err)
	}
	vars := fiber.Map{"sy_run": res}
	if err != nil {
		vars["sy_error"] = TC(c, "sync.admin_run_failed")
	}
	return r.renderSyncStatus(c, vars, "last")
}

// AdminSyncApply checks the plan in the request, then applies it past the
// brake in the admin's name in the background: a long run would outlast a
// proxy's request timeout. It refuses when the plan now locks or deletes
// more than the admin saw.
func (r *Router) AdminSyncApply(c fiber.Ctx) error {
	if !r.sync.on() {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	admin := r.username(c)
	// a missing count is 0: nothing to lock or delete was seen
	disable, _ := strconv.Atoi(c.FormValue("disable"))
	del, _ := strconv.Atoi(c.FormValue("delete"))
	release, ok, err := r.lock.claimKept(syncRunKey, syncRunTTL)
	if !ok {
		return r.syncBusy(c, err)
	}
	fresh, err := r.syncRun(context.Background(), time.Now(), admin, true)
	if err != nil {
		release()
		return r.renderSyncStatus(c, fiber.Map{"sy_error": TC(c, "sync.admin_run_failed")}, "")
	}
	if len(fresh.Plan.Disable) > disable || len(fresh.Plan.Delete) > del {
		// a reload shows the plan the admin now has to check
		if err := r.syncStoreHeld(syncHeldOf(time.Now(), fresh.Plan, fresh.SkipReasons)); err != nil {
			slog.Error("Failed to store the fresh held sync plan", "admin", admin, "err", err)
		}
		release()
		slog.Warn("Admin sync apply refused, the plan grew", "admin", admin,
			"disable", disable, "now_disable", len(fresh.Plan.Disable), "delete", del, "now_delete", len(fresh.Plan.Delete))
		return r.renderSyncStatus(c, fiber.Map{"sy_fresh": fresh, "sy_alert": TC(c, "sync.admin_plan_changed")}, "held")
	}
	r.goBG(func() {
		defer release()
		// a second read: Google may have shrunk since the check
		if _, err := r.syncRunCapped(context.Background(), time.Now(), admin, false, &syncCaps{Disable: disable, Delete: del}); err != nil {
			slog.Error("Admin sync apply failed", "admin", admin, "err", err)
		}
	})
	return r.renderSyncStatus(c, fiber.Map{}, "last")
}

// AdminSyncImportLegacy tags the google2ipa locks once; afterwards
// import_google2ipa_locks has no effect.
func (r *Router) AdminSyncImportLegacy(c fiber.Ctx) error {
	if !r.sync.on() {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	release, ok, err := r.lock.claimKept(syncRunKey, syncRunTTL)
	if !ok {
		return r.syncBusy(c, err)
	}
	defer release()
	pending, err := r.syncLegacyPending()
	if err != nil {
		slog.Error("Failed to read the google2ipa import marker", "err", err)
		return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "account.fatal_system_error"))
	}
	if !pending {
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	admin, now := r.username(c), time.Now()
	fail := func(msg string, args ...any) error {
		slog.Error(msg, append(args, "by", admin)...)
		return r.renderSyncStatus(c, fiber.Map{"sy_error": TC(c, "account.fatal_system_error")}, "decisions")
	}
	cands, err := r.syncLegacyCandidates(c.Context(), now)
	if err != nil {
		return fail("Failed to list google2ipa locks", "err", err)
	}
	for _, uid := range cands {
		u, err := r.adminClient.UserShow(uid)
		if err != nil {
			return fail("Failed to read the google2ipa lock date", "username", uid, "err", err)
		}
		m, err := r.syncGetMarker(uid)
		if err != nil {
			return fail("Failed to read the sync marker", "username", uid, "err", err)
		}
		at := u.PrincipalExpire
		if m != nil && m.At.Before(at) {
			at = m.At
		}
		if err := r.syncSetMarker(uid, syncMarker{Kind: syncMarkerLegacy, At: at, By: admin}); err != nil {
			return fail("Failed to write the sync marker", "username", uid, "err", err)
		}
		slog.Info("AUDIT sync google2ipa lock imported", "username", uid, "by", admin, "locked_at", at)
	}
	if err := r.storage.Set(syncLegacyKey, []byte(now.UTC().Format(time.RFC3339)), 0); err != nil {
		return fail("Failed to record the google2ipa import", "err", err)
	}
	return r.renderSyncStatus(c, fiber.Map{"sy_done": fmt.Sprintf(TC(c, "sync.admin_imported"), len(cands))}, "decisions")
}
