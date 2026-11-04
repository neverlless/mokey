package server

// Password-expiry reminder emails. A background sweep finds users whose
// passwords expire within the configured reminder windows and emails each
// user once per window, deduplicated through the storage backend. Replaces
// standalone cron tools like freeipa-pen / ipa-notify.

import (
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/gofiber/fiber/v2"
	ipa "github.com/neverlless/goipa"
	"github.com/spf13/viper"
)

const (
	expiryReminderPrefix = "expiry-reminder-"
	expirySweepInterval  = 6 * time.Hour
)

// expiryReminderDays returns the configured reminder windows (days before
// expiry), smallest first. Empty = feature disabled.
func expiryReminderDays() []int {
	days := viper.GetIntSlice("email.password_expiry_reminders")
	sort.Ints(days)
	return days
}

// StartExpiryReminders launches the background sweep when reminders are
// configured. Runs for the lifetime of the process.
func (r *Router) StartExpiryReminders() {
	if len(expiryReminderDays()) == 0 {
		return
	}

	slog.Info("Password expiry reminders enabled",
		"reminder_days", expiryReminderDays(),
	)

	go func() {
		// ponytail: single-instance sweep; multi-replica deployments send
		// at most one duplicate per window thanks to the storage marker,
		// and only when replicas race within the same sweep
		for {
			r.expiryReminderSweep()
			time.Sleep(expirySweepInterval)
		}
	}()
}

// expiryReminderSweep emails every user whose password expires within a
// reminder window and hasn't been reminded for that window yet
func (r *Router) expiryReminderSweep() {
	users, err := r.adminClient.UserFind(ipa.Options{
		"sizelimit": 0,
		"timelimit": 0,
	})
	if err != nil {
		slog.Error("Password expiry sweep failed to list users",
			"err", err,
		)
		return
	}

	now := time.Now()
	sent := 0
	for _, user := range users {
		if user.Locked || user.Email == "" || user.PasswdExpire.IsZero() {
			continue
		}

		left := user.PasswdExpire.Sub(now)
		if left <= 0 {
			continue // already expired; login flow handles that
		}

		// tightest applicable window: smallest configured threshold the
		// remaining time already fits into. One email per user+expiry+
		// window; markers die with the expiry date, so a password change
		// re-arms every window.
		for _, days := range expiryReminderDays() {
			if left > time.Duration(days)*24*time.Hour {
				continue
			}

			marker := fmt.Sprintf("%s%s-%d-%d", expiryReminderPrefix, user.Username, user.PasswdExpire.Unix(), days)
			if existing, _ := r.storage.Get(marker); existing != nil {
				break
			}

			if err := r.emailer.SendPasswordExpiryReminderEmail(user, int(left.Hours()/24)+1); err != nil {
				slog.Error("Failed to send password expiry reminder",
					"username", user.Username,
					"err", err,
				)
				break // no marker — retried next sweep
			}

			if err := r.storage.Set(marker, []byte("sent"), time.Until(user.PasswdExpire)+24*time.Hour); err != nil {
				slog.Warn("Failed to record password expiry reminder, it may be sent again",
					"username", user.Username,
					"err", err,
				)
			}
			slog.Info("Password expiry reminder sent",
				"username", user.Username,
				"days", days,
			)
			sent++
			break
		}
	}

	if sent > 0 {
		slog.Info("Password expiry sweep complete",
			"sent", sent,
		)
	}
}

// passwordExpiresInDays returns the whole days until the user's password
// expires, or -1 when there is no expiry set
func passwordExpiresInDays(user *ipa.User) int {
	if user.PasswdExpire.IsZero() {
		return -1
	}
	left := time.Until(user.PasswdExpire)
	if left < 0 {
		return 0
	}
	return int(left.Hours() / 24)
}

// expiryWarningVars adds the expiry banner variables when the user's
// password expires within accounts.password_expiry_warning_days
func expiryWarningVars(user *ipa.User, vars fiber.Map) {
	warnDays := viper.GetInt("accounts.password_expiry_warning_days")
	if warnDays <= 0 {
		return
	}

	days := passwordExpiresInDays(user)
	if days >= 0 && days <= warnDays {
		vars["password_expiry_warning"] = true
		vars["password_expiry_days"] = days
	}
}
