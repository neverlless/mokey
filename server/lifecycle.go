package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	ipa "github.com/neverlless/goipa"
)

const (
	lifecycleInterval = 6 * time.Hour
	lifecycleHeldKey  = "lifecycle-held"
	lcRemindPrefix    = "lc-remind-"
	lcHeldSample      = 20

	lcAuditSet      = "AUDIT lifecycle expiry set"
	lcAuditExtended = "AUDIT lifecycle expiry extended"
)

// lcHeld is a plan the brake stopped, kept for the admin page.
type lcHeld struct {
	Count  int
	At     time.Time
	Sample []lcChange
}

// StartLifecycle runs the account lifecycle sweep for the lifetime of the
// process.
func (r *Router) StartLifecycle() {
	if !r.lifecycle.on() {
		return
	}
	slog.Info("Account lifecycle sweep enabled", "interval", lifecycleInterval)
	startLoop(func() {
		for {
			r.lifecycleSweep(time.Now())
			time.Sleep(lifecycleInterval)
		}
	})
}

func (r *Router) lifecycleSweep(now time.Time) {
	if !r.lock.lease("lifecycle", lifecycleInterval) {
		return
	}
	if _, _, err := r.lifecycleRun(now, false); err != nil {
		slog.Error("Account lifecycle sweep could not list users", "err", err)
	}
}

// lifecycleRun applies the planned expiry changes and sends reminders.
// Without force a plan larger than max_changes_per_run is held, not applied.
func (r *Router) lifecycleRun(now time.Time, force bool) (applied int, held *lcHeld, err error) {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()

	// one FreeIPA call per run; ipa.User lacks manager
	entries, err := ipa.FindEntries(context.Background(), r.adminClient, "user_find", nil,
		ipa.Options{"all": true, "no_members": true, "sizelimit": 0, "timelimit": 0}, 0)
	truncated := errors.Is(err, ipa.ErrTruncated)
	if err != nil && !truncated {
		return 0, nil, err
	}

	accts := make([]lcAccount, 0, len(entries))
	users := make(map[string]*ipa.User, len(entries))
	for _, e := range entries {
		uid := e.Str("uid")
		accts = append(accts, lcAccount{
			UID:      uid,
			Sponsor:  sponsorUID(e.Str("manager")),
			Expires:  e.Time("krbprincipalexpiration"),
			Disabled: e.Bool("nsaccountlock"),
		})
		users[uid] = &ipa.User{
			Username:          uid,
			First:             e.Str("givenname"),
			Last:              e.Str("sn"),
			DisplayName:       e.Str("displayname"),
			Email:             e.Str("mail"),
			PreferredLanguage: e.Str("preferredlanguage"),
		}
	}

	if truncated {
		slog.Warn("Account lifecycle sweep got a truncated user list, skipping expiry changes this run; raise the FreeIPA search size limit",
			"users", len(entries))
	} else {
		applied, held = r.lifecycleApply(accts, now, force)
	}
	r.lifecycleRemind(accts, users, now)
	return applied, held, nil
}

func (r *Router) lifecycleApply(accts []lcAccount, now time.Time, force bool) (int, *lcHeld) {
	changes, _ := planLifecycle(accts, now, r.lifecycle)
	if len(changes) > r.lifecycle.MaxChanges && !force {
		held := &lcHeld{Count: len(changes), At: now, Sample: changes[:min(len(changes), lcHeldSample)]}
		slog.Warn("Account lifecycle changes held: more than lifecycle.max_changes_per_run, apply them from the admin Lifecycle page",
			"changes", len(changes),
			"max_changes_per_run", r.lifecycle.MaxChanges,
		)
		b, err := json.Marshal(held)
		if err == nil {
			err = r.storage.Set(lifecycleHeldKey, b, 0)
		}
		if err != nil {
			slog.Error("Failed to store held lifecycle changes", "err", err)
		}
		return 0, held
	}
	if err := r.storage.Delete(lifecycleHeldKey); err != nil {
		slog.Error("Failed to clear held lifecycle changes", "err", err)
	}
	if len(changes) == 0 {
		return 0, nil
	}

	// more lines than webhook queues hold: webhooks get the summary only
	var bulk []any
	if len(changes) > webhookQueueSize/2 {
		bulk = []any{"bulk", true}
	}
	idx := make(map[string]int, len(accts))
	for i, a := range accts {
		idx[a.UID] = i
	}
	applied, failed := 0, 0
	for _, c := range changes {
		if err := r.writeExpiry(c.UID, c.To, "system", lcAuditSet, append([]any{"reason", c.Reason, "from", c.From}, bulk...)...); err != nil {
			failed++
			continue
		}
		applied++
		// reminders below see the new date
		accts[idx[c.UID]].Expires = c.To
	}
	slog.Info("AUDIT lifecycle run applied", "by", "system", "count", applied, "failed", failed, "planned", len(changes))
	return applied, nil
}

// lifecycleHeld returns the plan the brake last held, or nil.
func (r *Router) lifecycleHeld() (*lcHeld, error) {
	raw, err := r.storage.Get(lifecycleHeldKey)
	if err != nil || raw == nil {
		return nil, err
	}
	held := &lcHeld{}
	if err := json.Unmarshal(raw, held); err != nil {
		return nil, err
	}
	return held, nil
}

// applyExpiry sets uid's expiry as by; an extension mails the user.
func (r *Router) applyExpiry(uid string, to time.Time, by, audit string) error {
	if err := r.writeExpiry(uid, to, by, audit); err != nil {
		return err
	}
	if audit != lcAuditExtended {
		return nil
	}
	user, err := r.adminClient.UserShow(uid)
	if err != nil {
		slog.Error("Failed to fetch user for account extended email", "username", uid, "err", err)
		return nil
	}
	if err := r.emailer.SendAccountExtendedEmail(user, to); err != nil {
		slog.Error("Failed to send account extended email", "username", uid, "err", err)
	}
	return nil
}

func (r *Router) writeExpiry(uid string, to time.Time, by, audit string, attrs ...any) error {
	if err := setUserExpiry(r.adminClient, uid, to); err != nil {
		slog.Error("FreeIPA refused the account expiry change; does mokey's role have the Mokey Modify Principal Expiration permission?",
			"username", uid,
			"by", by,
			"err", err,
		)
		return err
	}
	slog.Info(audit, append([]any{"username", uid, "by", by, "to", to.UTC()}, attrs...)...)
	return nil
}

func lcRemindMarker(uid string, days int, expires time.Time) string {
	return fmt.Sprintf("%s%s-%d-%s", lcRemindPrefix, uid, days, expires.UTC().Format("20060102"))
}

// lifecycleRemind mails each enabled account once in the tightest reminder
// window its expiry falls into, and its sponsor with it.
func (r *Router) lifecycleRemind(accts []lcAccount, users map[string]*ipa.User, now time.Time) {
	for _, a := range accts {
		user := users[a.UID]
		left := a.Expires.Sub(now)
		if a.Disabled || a.Expires.IsZero() || left <= 0 || user.Email == "" {
			continue
		}
		window := 0
		for _, days := range r.lifecycle.Reminders {
			if left <= time.Duration(days)*24*time.Hour {
				window = days // largest first: the last fit is the tightest
			}
		}
		if window == 0 {
			continue
		}
		marker := lcRemindMarker(a.UID, window, a.Expires)
		if existing, _ := r.storage.Get(marker); existing != nil {
			continue
		}
		if err := r.emailer.SendAccountExpiringEmail(user, a.Expires); err != nil {
			slog.Error("Failed to send account expiry reminder", "username", a.UID, "err", err)
			continue
		}
		if sponsor := users[a.Sponsor]; sponsor != nil && sponsor.Email != "" {
			if err := r.emailer.SendSponsoredExpiringEmail(sponsor, user, a.Expires); err != nil {
				slog.Error("Failed to send sponsored account expiry reminder", "username", a.UID, "sponsor", a.Sponsor, "err", err)
			}
		}
		if err := r.storage.Set(marker, []byte("sent"), left+24*time.Hour); err != nil {
			slog.Warn("Failed to record account expiry reminder, it may be sent again", "username", a.UID, "err", err)
		}
		slog.Info("Account expiry reminder sent", "username", a.UID, "days", window)
	}
}
