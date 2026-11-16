package server

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

type lcPlanRow struct {
	UID      string
	From, To time.Time
	Why      string
}

type lcOrphanRow struct {
	UID, Sponsor   string
	SponsorExpires time.Time
}

// lifecycleStatusVars fills the admin Lifecycle page from one user_find,
// the same plan the next run would apply.
func (r *Router) lifecycleStatusVars(c fiber.Ctx, vars fiber.Map) {
	lang := requestLanguage(c)
	cfg := r.lifecycle
	vars["user"] = r.user(c)
	if len(cfg.Reminders) > 0 {
		days := make([]string, len(cfg.Reminders))
		for i, d := range cfg.Reminders {
			days[i] = strconv.Itoa(d)
		}
		vars["lc_reminders"] = fmt.Sprintf(TL(lang, "admin.lifecycle_on_value"),
			fmt.Sprintf(TL(lang, "admin.lifecycle_reminder_days"), strings.Join(days, ", ")))
	}
	if cfg.Renewal > 0 {
		vars["lc_renewal"] = fmt.Sprintf(TL(lang, "admin.lifecycle_on_value"), formatDuration(lang, cfg.Renewal))
	}
	vars["lc_assign"] = cfg.AssignMissing

	held, err := r.lifecycleHeld()
	if err != nil {
		slog.Error("Failed to read held lifecycle changes", "err", err)
	}
	accts, _, truncated, err := r.lifecycleAccounts()
	if err != nil {
		slog.Error("Failed to list users for the lifecycle page", "err", err)
		vars["lc_error"] = TL(lang, "account.fatal_system_error")
		return
	}
	vars["lc_truncated"] = truncated

	now := time.Now()
	sponsors := make(map[string]string, len(accts))
	expires := make(map[string]time.Time, len(accts))
	for _, a := range accts {
		sponsors[a.UID], expires[a.UID] = a.Sponsor, a.Expires
	}
	changes, orphans := planLifecycle(accts, now, cfg)

	if held != nil && len(changes) > 0 {
		vars["lc_held"] = fmt.Sprintf(TL(lang, "admin.lifecycle_held"), held.Count, cfg.MaxChanges)
		rows := make([]lcPlanRow, 0, min(len(changes), lcHeldSample))
		for _, ch := range changes[:min(len(changes), lcHeldSample)] {
			why := "admin.lifecycle_why_cap"
			if ch.Reason == "assign" {
				why = "admin.lifecycle_why_assign"
			}
			rows = append(rows, lcPlanRow{UID: ch.UID, From: ch.From, To: ch.To, Why: fmt.Sprintf(TL(lang, why), sponsors[ch.UID])})
		}
		vars["lc_changes"] = rows
		if more := len(changes) - len(rows); more > 0 {
			vars["lc_more"] = fmt.Sprintf(TL(lang, "admin.lifecycle_more"), more)
		}
		vars["lc_apply"] = fmt.Sprintf(TL(lang, "admin.lifecycle_apply"), formatUnit(lang, "change", len(changes)))
	}

	rows := make([]lcOrphanRow, 0, len(orphans))
	for _, uid := range orphans {
		rows = append(rows, lcOrphanRow{UID: uid, Sponsor: sponsors[uid], SponsorExpires: expires[sponsors[uid]]})
	}
	vars["lc_orphans"] = rows
}

func (r *Router) renderLifecycleStatus(c fiber.Ctx, vars fiber.Map) error {
	r.lifecycleStatusVars(c, vars)
	return c.Render("admin-lifecycle-status.html", vars)
}

func (r *Router) AdminLifecycleStatus(c fiber.Ctx) error {
	if !r.lifecycle.on() {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	return r.renderLifecycleStatus(c, fiber.Map{})
}

// AdminLifecycleApply runs the plan past the brake in the admin's name. It
// recomputes the plan, so a second click finds nothing left to apply.
func (r *Router) AdminLifecycleApply(c fiber.Ctx) error {
	if !r.lifecycle.on() {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	vars := fiber.Map{}
	applied, _, err := r.lifecycleRun(time.Now(), r.username(c))
	switch {
	case errors.Is(err, errLifecycleTruncated):
		vars["lc_failed"] = TC(c, "admin.lifecycle_truncated")
	case err != nil:
		slog.Error("Admin lifecycle apply failed", "admin", r.username(c), "err", err)
		vars["lc_failed"] = TC(c, "account.fatal_system_error")
	case applied > 0:
		vars["lc_notice"] = fmt.Sprintf(TC(c, "admin.lifecycle_applied"), formatUnit(requestLanguage(c), "change", applied))
	}
	return r.renderLifecycleStatus(c, vars)
}

// adminLifecycleAction handles set-expiry and set-sponsor; both write with
// the admin client and are audited in the admin's name.
func (r *Router) adminLifecycleAction(c fiber.Ctx, action, username string) error {
	if !r.lifecycle.on() {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	admin := r.username(c)
	var notice string
	switch action {
	case "set-expiry":
		var to time.Time
		if v := strings.TrimSpace(c.FormValue("expires")); v != "" {
			var err error
			if to, err = time.ParseInLocation("2006-01-02", v, time.Local); err != nil {
				return c.Status(fiber.StatusBadRequest).SendString(TC(c, "admin.lifecycle_expiry_invalid"))
			}
		}
		if err := r.applyExpiry(username, to, admin, lcAuditSet); err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "admin.lifecycle_write_failed"))
		}
		day := to.Format(TC(c, "date.day_layout"))
		switch {
		case to.IsZero():
			notice = fmt.Sprintf(TC(c, "admin.lifecycle_expiry_cleared"), username)
		case !to.After(time.Now()):
			notice = fmt.Sprintf(TC(c, "admin.lifecycle_expiry_expired"), username, day)
		default:
			notice = fmt.Sprintf(TC(c, "admin.lifecycle_expiry_set"), username, day)
		}
	case "set-sponsor":
		sponsor := strings.TrimSpace(c.FormValue("sponsor"))
		if strings.EqualFold(sponsor, username) {
			return c.Status(fiber.StatusBadRequest).SendString(TC(c, "admin.lifecycle_sponsor_self"))
		}
		if sponsor != "" {
			accts, _, truncated, err := r.lifecycleAccounts()
			if err != nil || truncated {
				slog.Error("Failed to list users for the sponsor loop check", "username", username, "truncated", truncated, "err", err)
				return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "account.fatal_system_error"))
			}
			current := make(map[string]string, len(accts))
			for _, a := range accts {
				current[a.UID] = a.Sponsor
			}
			if _, ok := current[sponsor]; !ok {
				return c.Status(fiber.StatusBadRequest).SendString(TC(c, "admin.lifecycle_sponsor_unknown"))
			}
			if sponsorLoop(current, username, sponsor) {
				return c.Status(fiber.StatusBadRequest).SendString(TC(c, "admin.lifecycle_sponsor_loop"))
			}
		}
		if err := setUserSponsor(r.adminClient, username, sponsor); err != nil {
			slog.Error("Failed to set the account sponsor", "username", username, "sponsor", sponsor, "by", admin, "err", err)
			return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "admin.lifecycle_write_failed"))
		}
		slog.Info("AUDIT lifecycle sponsor set", "username", username, "sponsor", sponsor, "by", admin, "ip", RemoteIP(c))
		notice = fmt.Sprintf(TC(c, "admin.lifecycle_sponsor_set"), username, sponsor)
		if sponsor == "" {
			notice = fmt.Sprintf(TC(c, "admin.lifecycle_sponsor_cleared"), username)
		}
	}

	if c.FormValue("from") == "lifecycle" {
		return r.renderLifecycleStatus(c, fiber.Map{"lc_notice": notice})
	}
	vars := r.adminUserVars(c, c.FormValue("search"), pageParam(c.FormValue("page")))
	vars["lifecycle_notice"] = notice
	return c.Render("admin-users.html", vars)
}
