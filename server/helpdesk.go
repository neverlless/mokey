package server

// Helpdesk view of the admin panel: accounts whose password expires soon or
// has expired, accounts locked out by failed logins and accounts nobody has
// shown a sign of life for a while. One user_find feeds all four lists.

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
	// Source of an inactive row's date: mokey, password or ipa
	Source string
}

type helpdeskReport struct {
	Rows      map[string][]helpdeskRow
	Truncated bool
	// NoActivity counts accounts with no sign of life from any source
	NoActivity int
	// LoginsUnrecorded is true when the KDC does not write
	// krbLastSuccessfulAuth (FreeIPA's default)
	LoginsUnrecorded bool
	// Unreachable lists the masters whose logins could not be read
	Unreachable []string
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

type ipaConfig struct {
	ConfigString []string `json:"ipaconfigstring"`
	Masters      []string `json:"ipa_master_server"`
}

// readIPAConfig returns FreeIPA's global configuration; zero when
// config_show fails
func readIPAConfig(client *ipa.Client) ipaConfig {
	var config ipaConfig
	// shortcut: raw config_show until goipa has a typed call (neverlless/goipa#23)
	res, err := client.RPC("config_show", nil, ipa.Options{"all": true})
	if err != nil || res.Result == nil {
		slog.Warn("Failed to read the FreeIPA configuration", "err", err)
		return config
	}
	if err := json.Unmarshal(res.Result.Data, &config); err != nil {
		slog.Warn("Failed to decode the FreeIPA configuration", "err", err)
	}
	return config
}

// masterLastAuth reads krbLastSuccessfulAuth of every user from one master:
// FreeIPA does not replicate it, each master keeps the logins it saw
func (r *Router) masterLastAuth(host string) (map[string]time.Time, error) {
	client, err := newIPAClientForHost(host)
	if err != nil {
		return nil, err
	}
	if err := ipaKeytabLogin(client, viper.GetString("site.keytab"), viper.GetString("site.ktuser")); err != nil {
		return nil, err
	}
	client.StickySession(false)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	entries, err := ipa.FindEntries(ctx, client, "user_find", nil, ipa.Options{"all": true, "no_members": true}, helpdeskSizeLimit)
	if err != nil && !errors.Is(err, ipa.ErrTruncated) {
		return nil, err
	}
	logins := map[string]time.Time{}
	for _, e := range entries {
		if last := e.Time("krblastsuccessfulauth"); !last.IsZero() {
			logins[e.Str("uid")] = last
		}
	}
	return logins, nil
}

// otherMastersLastAuth merges the logins recorded by every master except
// the one mokey talks to, keeping the latest per user
func (r *Router) otherMastersLastAuth(client *ipa.Client, masters []string) (map[string]time.Time, []string) {
	self, _, _ := strings.Cut(client.Host(), ":")
	merged := map[string]time.Time{}
	var unreachable []string
	// shortcut: masters are read one after another; parallelise if large
	// topologies make the helpdesk page slow
	for _, host := range masters {
		if strings.EqualFold(host, self) {
			continue
		}
		logins, err := r.masterLastAuth(host)
		if err != nil {
			slog.Warn("Failed to read logins from a FreeIPA master", "host", host, "err", err)
			unreachable = append(unreachable, host)
			continue
		}
		for uid, t := range logins {
			if t.After(merged[uid]) {
				merged[uid] = t
			}
		}
	}
	return merged, unreachable
}

func (r *Router) buildHelpdeskReport(now time.Time, expiringDays, inactiveDays int) (*helpdeskReport, error) {
	client := r.adminClient
	// FindEntries rather than UserFind: it reports FreeIPA's truncated flag
	// and keeps krbloginfailedcount, which ipa.User does not carry
	entries, err := ipa.FindEntries(context.Background(), client, "user_find", nil, ipa.Options{"all": true, "no_members": true}, helpdeskSizeLimit)
	truncated := errors.Is(err, ipa.ErrTruncated)
	if err != nil && !truncated {
		return nil, err
	}

	report := &helpdeskReport{Rows: map[string][]helpdeskRow{}, Truncated: truncated}
	config := readIPAConfig(client)
	report.LoginsUnrecorded = slices.Contains(config.ConfigString, disableLastSuccess)
	remoteLogins := map[string]time.Time{}
	if !report.LoginsUnrecorded {
		remoteLogins, report.Unreachable = r.otherMastersLastAuth(client, config.Masters)
	}

	for _, e := range entries {
		row := helpdeskRow{
			Username: e.Str("uid"),
			Name:     strings.TrimSpace(e.Str("givenname") + " " + e.Str("sn")),
			Email:    e.Str("mail"),
			Disabled: e.Bool("nsaccountlock"),
		}
		add := func(view string, date time.Time, source string) {
			r := row
			r.Date = date
			r.Source = source
			report.Rows[view] = append(report.Rows[view], r)
		}

		if exp := e.Time("krbpasswordexpiration"); !exp.IsZero() {
			if !exp.After(now) {
				add("expired", exp, "")
			} else if exp.Sub(now) <= time.Duration(expiringDays)*24*time.Hour {
				add("expiring", exp, "")
			}
		}

		if failed, _ := e.Int("krbloginfailedcount"); failed > 0 {
			// shortcut: one pwpolicy call per user with failed logins; match
			// users to pwpolicy_find by cospriority if this gets slow
			policy, err := client.UserPwPolicy(row.Username)
			if err != nil {
				slog.Error("Failed to fetch password policy", "username", row.Username, "err", err)
			} else if lastFailed := e.Time("krblastfailedauth"); lockedOut(policy, int(failed), lastFailed, now) {
				add("locked", lastFailed, "")
			}
		}

		ipaLogin := e.Time("krblastsuccessfulauth")
		if remote := remoteLogins[row.Username]; remote.After(ipaLogin) {
			ipaLogin = remote
		}
		var seen time.Time
		source := ""
		// shortcut: one storage read per user; batch them if a large
		// directory on Redis makes the page slow
		for _, s := range []struct {
			name string
			at   time.Time
		}{{"mokey", r.lastSignIn(row.Username)}, {"ipa", ipaLogin}, {"password", e.Time("krblastpwdchange")}} {
			if s.at.After(seen) {
				seen, source = s.at, s.name
			}
		}
		if seen.IsZero() {
			report.NoActivity++
		} else if now.Sub(seen) > time.Duration(inactiveDays)*24*time.Hour {
			add("inactive", seen, source)
		}
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

	report, err := r.buildHelpdeskReport(time.Now(), helpdeskExpiringDays(), viper.GetInt("admin.inactive_days"))
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
	vars["no_activity"] = report.NoActivity
	vars["logins_unrecorded"] = report.LoginsUnrecorded
	vars["unreachable"] = strings.Join(report.Unreachable, ", ")
	return vars
}

func (r *Router) AdminHelpdesk(c fiber.Ctx) error {
	return c.Render("admin-helpdesk.html", r.adminHelpdeskVars(c, c.Query("view")))
}
