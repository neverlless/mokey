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
	lifecycleRunKey   = "lifecycle-run"
	// longer than any Apply: it only frees the lock of a replica that died
	// mid-run
	lifecycleRunTTL  = time.Hour
	lifecycleLastKey = "lifecycle-last-apply"

	// FreeIPA ACIError: the bind lacks a permission
	ipaACIErrorCode = 2100

	lcAuditSet      = "AUDIT lifecycle expiry set"
	lcAuditExtended = "AUDIT lifecycle expiry extended"
)

var errLifecycleTruncated = errors.New("FreeIPA returned a truncated user list")

// lcHeld is a plan the brake stopped, kept for the admin page.
type lcHeld struct {
	Count  int
	At     time.Time
	Sample []lcChange
}

// lcLastApply is the outcome of the last admin Apply, for the admin page.
type lcLastApply struct {
	By              string
	At              time.Time
	Applied, Failed int
	Error           string // translation key
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
	release, ok, err := r.lock.claim(lifecycleRunKey, lifecycleRunTTL)
	switch {
	case err != nil:
		slog.Warn("Account lifecycle sweep skipped, storage unavailable", "err", err)
		return
	case !ok:
		slog.Info("Account lifecycle sweep skipped, an admin Apply is running")
		return
	}
	defer release()
	if _, _, err := r.lifecycleRun(now, ""); err != nil {
		slog.Error("Account lifecycle sweep could not list users", "err", err)
	}
}

// lifecycleRun applies the planned expiry changes; callers hold
// lifecycleRunKey. by "" is the sweep: it holds a plan larger than
// max_changes_per_run and sends reminders. An admin uid applies the whole
// plan in their name, sends no reminders and records the outcome for the
// admin page.
func (r *Router) lifecycleRun(now time.Time, by string) (applied int, held *lcHeld, err error) {
	if !r.lifecycle.on() {
		return 0, nil, nil
	}
	failed := 0
	if by != "" {
		defer func() { r.lifecycleSaveLastApply(by, now, applied, failed, err) }()
	}

	accts, users, truncated, err := r.lifecycleAccounts()
	if err != nil {
		return 0, nil, err
	}

	if truncated {
		slog.Warn("Account lifecycle sweep got a truncated user list, skipping expiry changes this run; raise the FreeIPA search size limit",
			"users", len(accts))
		if by != "" {
			return 0, nil, errLifecycleTruncated
		}
	} else {
		applied, failed, held = r.lifecycleApply(accts, now, by)
	}
	if by == "" {
		r.lifecycleRemind(accts, users, now)
	}
	return applied, held, nil
}

// lifecycleAccounts reads every account in one FreeIPA call; ipa.User lacks
// manager.
func (r *Router) lifecycleAccounts() (accts []lcAccount, users map[string]*ipa.User, truncated bool, err error) {
	entries, err := ipa.FindEntries(context.Background(), r.adminClient, "user_find", nil,
		ipa.Options{"all": true, "no_members": true, "sizelimit": 0, "timelimit": 0}, 0)
	truncated = errors.Is(err, ipa.ErrTruncated)
	if err != nil && !truncated {
		return nil, nil, false, err
	}
	accts = make([]lcAccount, 0, len(entries))
	users = make(map[string]*ipa.User, len(entries))
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
	return accts, users, truncated, nil
}

func (r *Router) lifecycleApply(accts []lcAccount, now time.Time, by string) (applied, failed int, held *lcHeld) {
	changes, _ := planLifecycle(accts, now, r.lifecycle)
	if len(changes) > r.lifecycle.MaxChanges && by == "" {
		held = &lcHeld{Count: len(changes), At: now, Sample: changes[:min(len(changes), lcHeldSample)]}
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
		return 0, 0, held
	}
	if err := r.storage.Delete(lifecycleHeldKey); err != nil {
		slog.Error("Failed to clear held lifecycle changes", "err", err)
	}
	if len(changes) == 0 {
		return 0, 0, nil
	}

	if by == "" {
		by = "system"
	}
	// an Apply past the brake: webhooks get the summary only
	var bulk []any
	if len(changes) > r.lifecycle.MaxChanges {
		bulk = []any{"bulk", true}
	}
	idx := make(map[string]int, len(accts))
	for i, a := range accts {
		idx[a.UID] = i
	}
	for _, c := range changes {
		if err := r.writeExpiry(c.UID, c.To, by, lcAuditSet, append([]any{"reason", c.Reason, "from", c.From}, bulk...)...); err != nil {
			failed++
			continue
		}
		applied++
		// reminders below see the new date
		accts[idx[c.UID]].Expires = c.To
	}
	slog.Info("AUDIT lifecycle run applied", "by", by, "count", applied, "failed", failed, "planned", len(changes))
	return applied, failed, nil
}

// lifecycleApplyInBackground starts an admin Apply unless a run holds
// lifecycleRunKey. A long Apply would outlast a proxy's request timeout.
func (r *Router) lifecycleApplyInBackground(by string) (started bool, err error) {
	release, ok, err := r.lock.claim(lifecycleRunKey, lifecycleRunTTL)
	if !ok {
		return false, err
	}
	r.goBG(func() {
		defer release()
		if _, _, err := r.lifecycleRun(time.Now(), by); err != nil {
			slog.Error("Admin lifecycle apply failed", "admin", by, "err", err)
		}
	})
	return true, nil
}

func (r *Router) lifecycleSaveLastApply(by string, at time.Time, applied, failed int, err error) {
	last := lcLastApply{By: by, At: at, Applied: applied, Failed: failed}
	switch {
	case errors.Is(err, errLifecycleTruncated):
		last.Error = "admin.lifecycle_truncated"
	case err != nil:
		last.Error = "account.fatal_system_error"
	}
	b, err := json.Marshal(last)
	if err == nil {
		err = r.storage.Set(lifecycleLastKey, b, 0)
	}
	if err != nil {
		slog.Error("Failed to store the lifecycle Apply result", "err", err)
	}
}

// lifecycleLastApply returns the outcome of the last admin Apply, or nil.
func (r *Router) lifecycleLastApply() (*lcLastApply, error) {
	raw, err := r.storage.Get(lifecycleLastKey)
	if err != nil || raw == nil {
		return nil, err
	}
	last := &lcLastApply{}
	if err := json.Unmarshal(raw, last); err != nil {
		return nil, err
	}
	return last, nil
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
		msg := "Failed to change the account expiry"
		var ierr *ipa.IpaError
		if errors.As(err, &ierr) && ierr.Code == ipaACIErrorCode {
			msg = "FreeIPA refused the account expiry change; does mokey's role have the Mokey Modify Principal Expiration permission?"
		}
		slog.Error(msg,
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
		sponsor := users[a.Sponsor]
		mailSponsor := sponsor != nil && sponsor.Email != ""
		if a.Disabled || a.Expires.IsZero() || left <= 0 || user.Email == "" && !mailSponsor {
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
		existing, err := r.storage.Get(marker)
		if err != nil {
			slog.Error("Failed to read account expiry reminder marker, skipping", "username", a.UID, "err", err)
			continue
		}
		if existing != nil {
			continue
		}
		sent := false
		if user.Email != "" {
			if err := r.emailer.SendAccountExpiringEmail(user, a.Expires); err != nil {
				slog.Error("Failed to send account expiry reminder", "username", a.UID, "err", err)
				continue
			}
			sent = true
		}
		if mailSponsor {
			if err := r.emailer.SendSponsoredExpiringEmail(sponsor, user, a.Expires); err != nil {
				slog.Error("Failed to send sponsored account expiry reminder", "username", a.UID, "sponsor", a.Sponsor, "err", err)
			} else {
				sent = true
			}
		}
		if !sent {
			continue
		}
		if err := r.storage.Set(marker, []byte("sent"), left+24*time.Hour); err != nil {
			slog.Warn("Failed to record account expiry reminder, it may be sent again", "username", a.UID, "err", err)
		}
		slog.Info("Account expiry reminder sent", "username", a.UID, "days", window)
	}
}
