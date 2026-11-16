package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
)

type sponsoredRow struct {
	UID, Name  string
	Expires    time.Time
	LastActive time.Time
	Pill       string // warn | danger | ""
	PillText   string
	Target     time.Time
	Disabled   string // translation key of the reason Extend is off
}

func (r *Router) sponsorRenewal() bool { return r.lifecycle.on() && r.lifecycle.Renewal > 0 }

// extendRefusal is the translation key of why sponsor (expiring at own)
// can't extend an account expiring at cur to target, or "".
func extendRefusal(now, own, cur, target time.Time) string {
	switch {
	case lcPast(own, now):
		return "groups.sponsored_you_expired"
	case cur.IsZero():
		return "groups.sponsored_no_end"
	case !target.After(cur):
		return "groups.sponsored_at_cap"
	}
	return ""
}

// sponsoredVars fills the "People you sponsor" section: one FreeIPA call.
func (r *Router) sponsoredVars(c fiber.Ctx, vars fiber.Map) {
	if !r.sponsorRenewal() {
		return
	}
	user := r.user(c)
	people, err := sponsoredBy(r.adminClient, user.Username)
	if err != nil {
		slog.Error("Failed to list sponsored accounts", "username", user.Username, "err", err)
		vars["groups_error"] = true
		return
	}
	if len(people) == 0 {
		return
	}

	lang := requestLanguage(c)
	now := time.Now()
	own := user.PrincipalExpire
	target := extendTarget(now, r.lifecycle.Renewal, own)
	rows := make([]sponsoredRow, 0, len(people))
	for _, p := range people {
		row := sponsoredRow{
			UID:        p.Username,
			Name:       displayName(p),
			Expires:    p.PrincipalExpire,
			LastActive: r.lastSignIn(p.Username),
			Target:     target,
			Disabled:   extendRefusal(now, own, p.PrincipalExpire, target),
		}
		switch left := p.PrincipalExpire.Sub(now); {
		case p.PrincipalExpire.IsZero():
		case left <= 0:
			row.Pill, row.PillText = "danger", TL(lang, "groups.sponsored_expired")
		case len(r.lifecycle.Reminders) > 0 && left <= time.Duration(r.lifecycle.Reminders[0])*24*time.Hour:
			row.Pill, row.PillText = "warn", fmt.Sprintf(TL(lang, "groups.sponsored_in"), formatUnit(lang, "day", int(math.Ceil(left.Hours()/24))))
		}
		rows = append(rows, row)
	}
	vars["sponsored"] = rows
	vars["sponsored_period"] = formatDuration(lang, r.lifecycle.Renewal)
	if !own.IsZero() && own.After(now) {
		vars["sponsored_own"] = own
	}
}

// SponsoredExtend renews an account the caller sponsors. The check is
// mokey's: the write runs as the service account, like admin actions.
func (r *Router) SponsoredExtend(c fiber.Ctx) error {
	if !r.sponsorRenewal() {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	user := r.user(c)
	uid := c.FormValue("username")
	if uid == "" {
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, "groups.sponsored_not_yours"))
	}

	e, _, err := ipa.Call[ipa.Entry](context.Background(), r.adminClient, "user_show", []string{uid}, ipa.Options{"all": true})
	if errors.Is(err, ipa.ErrNotFound) {
		return c.Status(fiber.StatusForbidden).SendString(TC(c, "groups.sponsored_not_yours"))
	}
	if err != nil {
		slog.Error("Failed to read sponsored account", "username", uid, "by", user.Username, "err", err)
		return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "account.fatal_system_error"))
	}
	if !strings.EqualFold(sponsorUID(e.Str("manager")), user.Username) {
		return c.Status(fiber.StatusForbidden).SendString(TC(c, "groups.sponsored_not_yours"))
	}

	now := time.Now()
	to := extendTarget(now, r.lifecycle.Renewal, user.PrincipalExpire)
	if reason := extendRefusal(now, user.PrincipalExpire, e.Time("krbprincipalexpiration"), to); reason != "" {
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, reason))
	}
	uid = e.Str("uid")
	if err := r.applyExpiry(uid, to, user.Username, lcAuditExtended); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "groups.sponsored_extend_failed"))
	}

	vars := fiber.Map{
		"user":          user,
		"groups_notice": fmt.Sprintf(TC(c, "groups.sponsored_extended"), uid, to.Format(TC(c, "date.day_layout"))),
	}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}
