package server

// Helpdesk view of the admin panel: accounts whose password expires soon or
// has expired, accounts locked out by failed logins and accounts nobody has
// logged into for a while. One user_find feeds all four lists.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
	"github.com/spf13/viper"
)

const (
	helpdeskSizeLimit = 5000
	helpdeskRowLimit  = 100

	// ipaconfigstring value that stops the KDC writing krbLastSuccessfulAuth;
	// FreeIPA sets it on install
	disableLastSuccess = "KDC:Disable Last Success"
)

var helpdeskViews = []string{"expiring", "expired", "locked", "inactive"}

type helpdeskRow struct {
	Username string
	Name     string
	Email    string
	Date     time.Time
	Disabled bool
}

type helpdeskReport struct {
	Rows      map[string][]helpdeskRow
	Truncated bool
	// LastLoginTracked is false when FreeIPA does not record successful
	// logins, so the inactive list would be empty for the wrong reason
	LastLoginTracked bool
}

// helpdeskExpiringDays is the "expires soon" window: the wider of the
// in-portal banner and the reminder email windows
func helpdeskExpiringDays() int {
	days := viper.GetInt("accounts.password_expiry_warning_days")
	if reminders := expiryReminderDays(); len(reminders) > 0 {
		days = max(days, reminders[len(reminders)-1])
	}
	return days
}

// lockedOut reports whether the KDC currently refuses the user for failed
// logins under policy p: the count reached maxfail and the lockout has not
// run out (a zero duration locks until an admin unlocks)
func lockedOut(p *ipa.PwPolicy, failed int, lastFailed, now time.Time) bool {
	if p.MaxFailures <= 0 || failed < p.MaxFailures {
		return false
	}
	return p.LockoutDuration == 0 || lastFailed.Add(p.LockoutDuration).After(now)
}

// lastSuccessDisabled reports whether FreeIPA is configured not to record
// successful logins; false when config_show fails
func lastSuccessDisabled(client *ipa.Client) bool {
	// shortcut: raw config_show until goipa has a typed call (neverlless/goipa#23)
	res, err := client.RPC("config_show", nil, nil)
	if err != nil || res.Result == nil {
		slog.Warn("Failed to read the FreeIPA configuration", "err", err)
		return false
	}
	var config struct {
		ConfigString []string `json:"ipaconfigstring"`
	}
	if err := json.Unmarshal(res.Result.Data, &config); err != nil {
		slog.Warn("Failed to decode the FreeIPA configuration", "err", err)
		return false
	}
	return slices.Contains(config.ConfigString, disableLastSuccess)
}

func buildHelpdeskReport(client *ipa.Client, now time.Time, expiringDays, inactiveDays int) (*helpdeskReport, error) {
	// FindEntries rather than UserFind: it reports FreeIPA's truncated flag
	// and keeps krbloginfailedcount, which ipa.User does not carry
	entries, err := ipa.FindEntries(context.Background(), client, "user_find", nil, ipa.Options{"no_members": true}, helpdeskSizeLimit)
	truncated := errors.Is(err, ipa.ErrTruncated)
	if err != nil && !truncated {
		return nil, err
	}

	report := &helpdeskReport{Rows: map[string][]helpdeskRow{}, Truncated: truncated}
	anyLastLogin := false
	for _, e := range entries {
		row := helpdeskRow{
			Username: e.Str("uid"),
			Name:     strings.TrimSpace(e.Str("givenname") + " " + e.Str("sn")),
			Email:    e.Str("mail"),
			Disabled: e.Bool("nsaccountlock"),
		}
		add := func(view string, date time.Time) {
			r := row
			r.Date = date
			report.Rows[view] = append(report.Rows[view], r)
		}

		if exp := e.Time("krbpasswordexpiration"); !exp.IsZero() {
			if !exp.After(now) {
				add("expired", exp)
			} else if exp.Sub(now) <= time.Duration(expiringDays)*24*time.Hour {
				add("expiring", exp)
			}
		}

		if failed, _ := e.Int("krbloginfailedcount"); failed > 0 {
			// shortcut: one pwpolicy call per user with failed logins; match
			// users to pwpolicy_find by cospriority if this gets slow
			policy, err := client.UserPwPolicy(row.Username)
			if err != nil {
				slog.Error("Failed to fetch password policy", "username", row.Username, "err", err)
			} else if lastFailed := e.Time("krblastfailedauth"); lockedOut(policy, int(failed), lastFailed, now) {
				add("locked", lastFailed)
			}
		}

		if last := e.Time("krblastsuccessfulauth"); !last.IsZero() {
			anyLastLogin = true
			if now.Sub(last) > time.Duration(inactiveDays)*24*time.Hour {
				add("inactive", last)
			}
		}
	}

	report.LastLoginTracked = anyLastLogin && !lastSuccessDisabled(client)
	if !report.LastLoginTracked {
		delete(report.Rows, "inactive")
	}

	for _, rows := range report.Rows {
		slices.SortFunc(rows, func(a, b helpdeskRow) int { return a.Date.Compare(b.Date) })
	}
	return report, nil
}

func (r *Router) adminHelpdeskVars(c fiber.Ctx, view string) fiber.Map {
	if !slices.Contains(helpdeskViews, view) {
		view = helpdeskViews[0]
	}
	vars := fiber.Map{
		"user":          r.user(c),
		"view":          view,
		"views":         helpdeskViews,
		"expiring_days": helpdeskExpiringDays(),
		"inactive_days": viper.GetInt("admin.inactive_days"),
		"row_limit":     helpdeskRowLimit,
	}

	report, err := buildHelpdeskReport(r.adminClient, time.Now(), helpdeskExpiringDays(), viper.GetInt("admin.inactive_days"))
	if err != nil {
		slog.Error("Failed to list users for the helpdesk view", "err", err)
		vars["helpdesk_message"] = TC(c, "account.fatal_system_error")
		return vars
	}

	counts := map[string]int{}
	for v, rows := range report.Rows {
		counts[v] = len(rows)
	}
	rows := report.Rows[view]
	if len(rows) > helpdeskRowLimit {
		rows = rows[:helpdeskRowLimit]
	}
	vars["counts"] = counts
	vars["rows"] = rows
	vars["total"] = counts[view]
	vars["truncated"] = report.Truncated
	vars["last_login_tracked"] = report.LastLoginTracked
	return vars
}

func (r *Router) AdminHelpdesk(c fiber.Ctx) error {
	return c.Render("admin-helpdesk.html", r.adminHelpdeskVars(c, c.Query("view")))
}
