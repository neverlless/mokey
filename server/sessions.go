package server

// Active-session inventory. Logins register the fiber session id in a
// per-user index kept in the storage backend; the security page lists them
// and lets the user revoke individual sessions or everything but the
// current one. Revocation deletes the session data itself, so the next
// request on that session id is anonymous.

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/mileusna/useragent"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	userSessionsPrefix = "usersessions-"
	// index TTL; refreshed on every login and on every listing that finds
	// a live session
	userSessionsTTL = 30 * 24 * time.Hour
	// cap per user — oldest entries fall off
	userSessionsMax = 20
)

type UserSession struct {
	SID       string    `json:"sid"`
	LoginTime time.Time `json:"login_time"`
	IP        string    `json:"ip"`
	Browser   string    `json:"browser"`
	OS        string    `json:"os"`
	// Current is computed at render time, never stored
	Current bool `json:"-"`
}

func (r *Router) loadSessionIndex(username string) []UserSession {
	raw, err := r.storage.Get(userSessionsPrefix + username)
	if err != nil || raw == nil {
		return nil
	}

	var sessions []UserSession
	if err := json.Unmarshal(raw, &sessions); err != nil {
		return nil
	}
	return sessions
}

func (r *Router) saveSessionIndex(username string, sessions []UserSession) {
	if len(sessions) == 0 {
		r.storage.Delete(userSessionsPrefix + username)
		return
	}

	raw, err := json.Marshal(sessions)
	if err != nil {
		return
	}
	r.storage.Set(userSessionsPrefix+username, raw, userSessionsTTL)
}

// recordUserSession registers a fresh login in the user's session index
func (r *Router) recordUserSession(c *fiber.Ctx, username, sid string) {
	ua := useragent.Parse(c.Get(fiber.HeaderUserAgent))

	sessions := r.loadSessionIndex(username)
	// replace any stale entry for the same sid (session id was just
	// regenerated on login, so collisions mean leftovers)
	kept := sessions[:0]
	for _, s := range sessions {
		if s.SID != sid {
			kept = append(kept, s)
		}
	}
	kept = append(kept, UserSession{
		SID:       sid,
		LoginTime: time.Now(),
		IP:        RemoteIP(c),
		Browser:   ua.Name,
		OS:        ua.OS,
	})
	if len(kept) > userSessionsMax {
		kept = kept[len(kept)-userSessionsMax:]
	}
	r.saveSessionIndex(username, kept)
}

// sessionAlive reports whether the session data still exists in storage
func (r *Router) sessionAlive(sid string) bool {
	raw, err := r.storage.Get(sid)
	return err == nil && raw != nil
}

// userSessions returns the user's live sessions, newest first, dropping
// dead index entries along the way. currentSID marks the caller's own
// session.
func (r *Router) userSessions(username, currentSID string) []UserSession {
	sessions := r.loadSessionIndex(username)

	live := make([]UserSession, 0, len(sessions))
	for _, s := range sessions {
		if !r.sessionAlive(s.SID) {
			continue
		}
		s.Current = s.SID == currentSID
		live = append(live, s)
	}

	if len(live) != len(sessions) {
		// strip Current before persisting (json:"-" makes this a no-op,
		// but keep the slice clean)
		r.saveSessionIndex(username, live)
	} else if len(live) > 0 {
		// refresh the index TTL while sessions are alive
		r.saveSessionIndex(username, sessions)
	}

	// newest first
	for i, j := 0, len(live)-1; i < j; i, j = i+1, j-1 {
		live[i], live[j] = live[j], live[i]
	}
	return live
}

// revokeUserSession destroys one of the user's own sessions. Ownership is
// enforced through the index — foreign sids are ignored.
func (r *Router) revokeUserSession(username, sid string) bool {
	sessions := r.loadSessionIndex(username)
	kept := sessions[:0]
	found := false
	for _, s := range sessions {
		if s.SID == sid {
			found = true
			continue
		}
		kept = append(kept, s)
	}
	if !found {
		return false
	}

	if err := r.storage.Delete(sid); err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Error("Failed to delete session data on revoke")
	}
	r.saveSessionIndex(username, kept)
	return true
}

// revokeOtherUserSessions destroys every session except the current one
// and returns how many were revoked
func (r *Router) revokeOtherUserSessions(username, currentSID string) int {
	sessions := r.loadSessionIndex(username)
	kept := sessions[:0]
	revoked := 0
	for _, s := range sessions {
		if s.SID == currentSID {
			kept = append(kept, s)
			continue
		}
		if err := r.storage.Delete(s.SID); err == nil {
			revoked++
		}
	}
	r.saveSessionIndex(username, kept)
	return revoked
}

// dropSessionFromIndex removes an index entry without touching session
// data (used on logout, where fiber destroys the session itself)
func (r *Router) dropSessionFromIndex(username, sid string) {
	sessions := r.loadSessionIndex(username)
	kept := sessions[:0]
	for _, s := range sessions {
		if s.SID != sid {
			kept = append(kept, s)
		}
	}
	r.saveSessionIndex(username, kept)
}

// SessionRevoke handles per-device revocation from the security page
func (r *Router) SessionRevoke(c *fiber.Ctx) error {
	username := r.username(c)
	sid := c.FormValue("sid")
	vars := fiber.Map{}

	sess, err := r.session(c)
	if err != nil {
		return err
	}

	if sid == "" || sid == sess.ID() {
		vars["message"] = T("security.cannot_revoke_current")
		return r.securityList(c, vars)
	}

	if r.revokeUserSession(username, sid) {
		log.WithFields(log.Fields{
			"username": username,
			"ip":       RemoteIP(c),
		}).Info("AUDIT User revoked a session")
	}

	return r.securityList(c, vars)
}

// SessionRevokeOthers signs the user out everywhere except this device
func (r *Router) SessionRevokeOthers(c *fiber.Ctx) error {
	username := r.username(c)

	sess, err := r.session(c)
	if err != nil {
		return err
	}

	revoked := r.revokeOtherUserSessions(username, sess.ID())
	if revoked > 0 {
		log.WithFields(log.Fields{
			"username": username,
			"revoked":  revoked,
			"ip":       RemoteIP(c),
		}).Info("AUDIT User signed out all other sessions")
	}

	return r.securityList(c, fiber.Map{})
}

// notifyNewLogin emails the user about a fresh sign-in when enabled.
// Sent from a goroutine — SMTP hiccups must not block the login response.
func (r *Router) notifyNewLogin(c *fiber.Ctx, username string) {
	if !viper.GetBool("email.notify_new_login") {
		return
	}

	ua := useragent.Parse(c.Get(fiber.HeaderUserAgent))
	ip := RemoteIP(c)

	go func() {
		user, err := r.adminClient.UserShow(username)
		if err != nil || user.Email == "" {
			return
		}
		if err := r.emailer.SendNewLoginEmail(user, ua.Name, ua.OS, ip); err != nil {
			log.WithFields(log.Fields{
				"username": username,
				"err":      err,
			}).Error("Failed to send new login email")
		}
	}()
}
