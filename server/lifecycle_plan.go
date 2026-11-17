package server

import (
	"slices"
	"strings"
	"time"
)

type lcAccount struct {
	UID, Sponsor string
	Expires      time.Time
	Disabled     bool
}

type lcChange struct {
	UID      string
	From, To time.Time
	Reason   string // assign | sponsor_cap
}

const lcMaxPasses = 10

// extendTarget is the date an account gets when renewed. Only a future
// sponsor date earlier than now+renewal caps it.
func extendTarget(now time.Time, renewal time.Duration, sponsorExpires time.Time) time.Time {
	t := now.Add(renewal)
	if !sponsorExpires.IsZero() && sponsorExpires.After(now) && sponsorExpires.Before(t) {
		return sponsorExpires
	}
	return t
}

// sponsorLoop reports whether making sponsor the sponsor of uid closes a loop.
func sponsorLoop(accts map[string]string, uid, sponsor string) bool {
	for i := 0; i <= len(accts) && sponsor != ""; i++ {
		if sponsor == uid {
			return true
		}
		sponsor = accts[sponsor]
	}
	return false
}

func lcPast(t, now time.Time) bool { return !t.IsZero() && !t.After(now) }

// planLifecycle computes the expiry assignments and sponsor caps due now;
// both need renewal on.
// Input UIDs must be unique and Sponsor already a plain uid. Changes are sorted by UID; disabled accounts are never changed.
func planLifecycle(accts []lcAccount, now time.Time, cfg *lifecycleConfig) (changes []lcChange, sponsorExpired []string) {
	accts = slices.Clone(accts)
	slices.SortFunc(accts, func(a, b lcAccount) int { return strings.Compare(a.UID, b.UID) })
	cur := make(map[string]time.Time, len(accts))
	for _, a := range accts {
		cur[a.UID] = a.Expires
	}
	first := map[string]lcChange{}

	set := func(a lcAccount, to time.Time, reason string) {
		c, ok := first[a.UID]
		if !ok {
			c = lcChange{UID: a.UID, From: a.Expires, Reason: reason}
		}
		c.To = to
		first[a.UID] = c
		cur[a.UID] = to
	}

	assign := cfg.AssignMissing && cfg.Renewal > 0
	if assign {
		for _, a := range accts {
			if a.Sponsor != "" && !a.Disabled && a.Expires.IsZero() && !lcPast(cur[a.Sponsor], now) {
				set(a, extendTarget(now, cfg.Renewal, cur[a.Sponsor]), "assign")
			}
		}
	}

	// the cap is part of renewal: reminders alone never write to FreeIPA
	for pass := 0; cfg.Renewal > 0 && pass < lcMaxPasses; pass++ {
		moved := false
		for _, a := range accts {
			sp := cur[a.Sponsor]
			if a.Sponsor == "" || a.Disabled || cur[a.UID].IsZero() || sp.IsZero() ||
				!cur[a.UID].After(sp) || !sp.After(now) {
				continue
			}
			set(a, sp, "sponsor_cap")
			moved = true
		}
		if !moved {
			break
		}
	}

	for _, a := range accts {
		sp := cur[a.Sponsor]
		unassigned := assign && cur[a.UID].IsZero()
		if a.Sponsor != "" && !a.Disabled && lcPast(sp, now) && (unassigned || cur[a.UID].After(sp)) {
			sponsorExpired = append(sponsorExpired, a.UID)
		}
	}
	for _, a := range accts {
		if c, ok := first[a.UID]; ok {
			changes = append(changes, c)
		}
	}
	return changes, sponsorExpired
}
