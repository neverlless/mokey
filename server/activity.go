package server

import (
	"log/slog"
	"time"
)

const lastSeenPrefix = "lastseen-"

// recordSignIn notes a successful sign-in through mokey. Best effort: a
// failed write never stops the sign-in.
func (r *Router) recordSignIn(username string, at time.Time) {
	if err := r.storage.Set(lastSeenPrefix+username, []byte(at.UTC().Format(time.RFC3339)), 0); err != nil {
		slog.Warn("Failed to record the sign-in time", "username", username, "err", err)
	}
}

// lastSignIn is the latest sign-in recorded by recordSignIn, zero if none
func (r *Router) lastSignIn(username string) time.Time {
	raw, err := r.storage.Get(lastSeenPrefix + username)
	if err != nil || raw == nil {
		if err != nil {
			slog.Warn("Failed to read the sign-in time", "username", username, "err", err)
		}
		return time.Time{}
	}
	at, err := time.Parse(time.RFC3339, string(raw))
	if err != nil {
		return time.Time{}
	}
	return at
}
