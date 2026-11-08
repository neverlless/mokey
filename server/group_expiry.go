package server

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	ipa "github.com/neverlless/goipa"
)

const (
	membershipExpiryInterval = 5 * time.Minute
	reconcileEvery           = 12 // sweeps, i.e. hourly
	membershipReminderPrefix = "membership-reminder-"
)

// startLoop runs a process-lifetime loop; tests replace it so no sweep
// outlives the test that built the router.
var startLoop = func(fn func()) { go fn() }

type expiryFailure struct {
	Group, Username string
	Since           time.Time
	Err             string
	// NoRecord: a grant left without its end date; kept until restart
	NoRecord bool
}

type expiryFailureSet struct {
	mu sync.Mutex
	m  map[[2]string]expiryFailure
}

// shouldRunMembershipExpiry: grants made while the feature was on must still
// end after it is turned off.
func (r *Router) shouldRunMembershipExpiry() bool {
	all, err := r.loadTimedMembers()
	if err != nil {
		slog.Error("Failed to read time-bound memberships, starting the membership expiry sweep anyway", "err", err)
		return true
	}
	if !r.groupExpiry.Enabled() && len(all) > 0 {
		slog.Warn("groups.durations is not set but time-bound memberships exist; they will still be removed when they end",
			"count", len(all),
		)
	}
	return r.groupExpiry.Enabled() || len(all) > 0
}

// StartMembershipExpiry removes time-bound memberships when they end.
// Runs for the lifetime of the process.
func (r *Router) StartMembershipExpiry() {
	if !r.shouldRunMembershipExpiry() {
		return
	}
	slog.Info("Membership expiry sweep enabled", "interval", membershipExpiryInterval)

	// shortcut: no leader lock across replicas, so each may send the same
	// expiry/reminder email once; add a lock if duplicates become a problem
	startLoop(func() {
		for run := 0; ; run++ {
			r.membershipExpirySweep(time.Now(), run%reconcileEvery == 0)
			time.Sleep(membershipExpiryInterval)
		}
	})
}

func (r *Router) membershipExpirySweep(now time.Time, reconcile bool) {
	all, err := r.loadTimedMembers()
	if err != nil {
		slog.Error("Membership expiry sweep could not read time-bound memberships", "err", err)
		return
	}

	groups := map[string]*ipaGroup{}
	for _, m := range all {
		if !m.Until.After(now) {
			r.expireMembership(m, now)
			continue
		}
		if reconcile && r.removedOutOfBand(m, groups) {
			continue
		}
		r.remindMembership(m, now)
	}
	r.pruneExpiryFailures(all)
}

// entryGone reports a removal refused because the group or the user no
// longer exists in FreeIPA
func entryGone(err error) bool {
	var ierr *ipa.IpaError
	return errors.Is(err, ipa.ErrNotFound) || errors.As(err, &ierr) && ierr.Code == 2100 && ierr.Message == "no such entry"
}

func (r *Router) expireMembership(m TimedMembership, now time.Time) {
	// a renewal approved since the sweep loaded the list wins
	cur, err := r.timedMember(m.Group, m.Username)
	if err != nil {
		slog.Error("Membership expiry could not re-read the record", "group", m.Group, "username", m.Username, "err", err)
		return
	}
	if cur == nil || cur.Until.After(now) {
		return
	}
	m = *cur

	err = groupRemoveMember(r.adminClient, m.Group, m.Username)
	if entryGone(err) {
		r.clearExpiryFailure(m)
		if _, err := r.dropTimedMemberIf(m.Group, m.Username, m.Until); err != nil {
			slog.Error("Failed to drop record of a deleted group or user", "group", m.Group, "username", m.Username, "err", err)
			return
		}
		slog.Info("Dropped ended membership of a group or user deleted in FreeIPA", "group", m.Group, "username", m.Username, "err", err)
		return
	}
	if err != nil {
		r.metrics.groupExpiryFailures.Inc()
		msg := "Membership expiry still failing"
		// one audit event per failure, not one per sweep
		if r.recordExpiryFailure(m, fmt.Sprintf("FreeIPA refused the removal; does mokey's role have the Mokey Expire Memberships privilege? %s", err)) {
			msg = "AUDIT group membership expiry failed"
		}
		slog.Error(msg,
			"group", m.Group,
			"username", m.Username,
			"err", err,
		)
		return
	}
	r.clearExpiryFailure(m)

	if dropped, err := r.dropTimedMemberIf(m.Group, m.Username, m.Until); err != nil {
		slog.Error("Failed to drop expired membership record, the next sweep retries",
			"group", m.Group,
			"username", m.Username,
			"err", err,
		)
	} else if !dropped {
		slog.Warn("Membership record changed while its expiry was processed; kept the new one",
			"group", m.Group,
			"username", m.Username,
		)
	}
	slog.Info("AUDIT group membership expired",
		"group", m.Group,
		"username", m.Username,
		"until", m.Until,
	)
	r.revokeConsentsOf(m.Username)

	user, err := r.adminClient.UserShow(m.Username)
	if err != nil {
		slog.Error("Failed to fetch user for membership expired email", "username", m.Username, "err", err)
		return
	}
	if err := r.emailer.SendGroupExpiredEmail(user, m.Group); err != nil {
		slog.Error("Failed to send membership expired email", "username", m.Username, "err", err)
	}
}

// removedOutOfBand drops the record of a member removed outside mokey, so a
// later re-add outside mokey is not removed by the sweep. groups caches
// group_show per sweep; nil marks a group that could not be read.
func (r *Router) removedOutOfBand(m TimedMembership, groups map[string]*ipaGroup) bool {
	g, seen := groups[m.Group]
	if !seen {
		var err error
		if g, err = groupShow(r.adminClient, m.Group); err != nil {
			slog.Error("Membership reconciliation could not read group", "group", m.Group, "err", err)
		}
		groups[m.Group] = g
	}
	if g == nil || slices.Contains(g.Members, m.Username) {
		return false
	}
	dropped, err := r.dropTimedMemberIf(m.Group, m.Username, m.Until)
	if err != nil {
		slog.Error("Failed to drop record of a membership removed outside mokey", "group", m.Group, "username", m.Username, "err", err)
		return false
	}
	// changed since the load: the list is stale for this record, skip it
	if !dropped {
		return true
	}
	slog.Info("Dropped end date of a membership removed outside mokey", "group", m.Group, "username", m.Username)
	return true
}

func membershipReminderMarker(m TimedMembership, lead time.Duration) string {
	return fmt.Sprintf("%s%s-%s-%d-%d", membershipReminderPrefix, m.Group, m.Username, m.Until.Unix(), int64(lead.Seconds()))
}

// remindMembership sends at most one reminder: the tightest lead the
// remaining time already fits into, as in expiryReminderSweep.
func (r *Router) remindMembership(m TimedMembership, now time.Time) {
	if r.groupExpiry == nil {
		return
	}
	left := m.Until.Sub(now)
	for _, lead := range r.groupExpiry.Reminders {
		if lead >= m.Until.Sub(m.GrantedAt) || left > lead {
			continue
		}
		marker := membershipReminderMarker(m, lead)
		if existing, _ := r.storage.Get(marker); existing != nil {
			return
		}
		user, err := r.adminClient.UserShow(m.Username)
		if err != nil {
			slog.Error("Failed to fetch user for membership reminder", "username", m.Username, "err", err)
			return
		}
		if err := r.emailer.SendGroupExpiryReminderEmail(user, m.Group, m.Until); err != nil {
			slog.Error("Failed to send membership reminder", "group", m.Group, "username", m.Username, "err", err)
			return
		}
		if err := r.storage.Set(marker, []byte("sent"), m.Until.Sub(now)+24*time.Hour); err != nil {
			slog.Warn("Failed to record membership reminder, it may be sent again", "group", m.Group, "username", m.Username, "err", err)
		}
		slog.Info("Membership reminder sent", "group", m.Group, "username", m.Username, "lead", lead)
		return
	}
}

// recordExpiryFailure reports whether the failure is new
func (r *Router) recordExpiryFailure(m TimedMembership, msg string) bool {
	return r.putExpiryFailure(expiryFailure{Group: m.Group, Username: m.Username, Err: msg})
}

// putExpiryFailure keeps the first Since of a repeated failure and reports
// whether the failure is new
func (r *Router) putExpiryFailure(f expiryFailure) bool {
	r.expiryFails.mu.Lock()
	defer r.expiryFails.mu.Unlock()
	if r.expiryFails.m == nil {
		r.expiryFails.m = map[[2]string]expiryFailure{}
	}
	key := [2]string{f.Group, f.Username}
	old, ok := r.expiryFails.m[key]
	f.Since = old.Since
	if !ok {
		f.Since = time.Now()
	}
	r.expiryFails.m[key] = f
	return !ok
}

// pruneExpiryFailures drops failures whose record is gone, e.g. removed by
// hand after the failure was listed
func (r *Router) pruneExpiryFailures(all []TimedMembership) {
	r.expiryFails.mu.Lock()
	defer r.expiryFails.mu.Unlock()
	for key, f := range r.expiryFails.m {
		if !f.NoRecord && !slices.ContainsFunc(all, func(m TimedMembership) bool { return m.Group == f.Group && m.Username == f.Username }) {
			delete(r.expiryFails.m, key)
		}
	}
}

func (r *Router) clearExpiryFailure(m TimedMembership) {
	r.expiryFails.mu.Lock()
	defer r.expiryFails.mu.Unlock()
	delete(r.expiryFails.m, [2]string{m.Group, m.Username})
}

// expiryFailures lists memberships that ended but could not be removed,
// oldest first.
func (r *Router) expiryFailures() []expiryFailure {
	r.expiryFails.mu.Lock()
	defer r.expiryFails.mu.Unlock()
	out := make([]expiryFailure, 0, len(r.expiryFails.m))
	for _, f := range r.expiryFails.m {
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b expiryFailure) int { return a.Since.Compare(b.Since) })
	return out
}
