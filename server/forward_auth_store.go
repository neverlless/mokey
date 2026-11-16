package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/url"
	"time"
)

const (
	faPendingPrefix = "fa-pending-"
	faCodePrefix    = "fa-code-"
	faSessPrefix    = "fa-sess-"
	faUserPrefix    = "fa-user-"
	faPendingTTL    = 10 * time.Minute
	faCodeTTL       = 60 * time.Second
	faTouchEvery    = time.Minute
)

type faPending struct {
	RD, Host, Nonce string
	Created         time.Time
}

type faCode struct {
	Username, Host, PendingID, ParentSID string
}

type faSession struct {
	ID, Username, Host, ParentSID string
	Created, LastSeen, CheckedAt  time.Time
	Groups                        []string
	Name, Email                   string
}

type faUserEntry struct {
	ID, ParentSID string
}

func faRandomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (r *Router) faPut(key string, v any, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return r.storage.Set(key, raw, ttl)
}

// faTake reads and deletes key under the strict lock, so a value is handed
// out at most once even across replicas; found is false for a missing key
func (r *Router) faTake(key string, v any) (found bool, err error) {
	release, err := r.lock.holdStrict(key)
	if err != nil {
		return false, err
	}
	defer release()

	raw, err := r.storage.Get(key)
	if err != nil || raw == nil {
		return false, err
	}
	if err := r.storage.Delete(key); err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, v)
}

func (r *Router) faNewPending(rd *url.URL, host string) (id, nonce string, err error) {
	if id, err = faRandomID(); err != nil {
		return "", "", err
	}
	if nonce, err = faRandomID(); err != nil {
		return "", "", err
	}
	p := faPending{RD: rd.String(), Host: host, Nonce: nonce, Created: time.Now()}
	if err := r.faPut(faPendingPrefix+id, p, faPendingTTL); err != nil {
		return "", "", err
	}
	return id, nonce, nil
}

func (r *Router) faTakePending(id string) (*faPending, error) {
	if id == "" {
		return nil, nil
	}
	var p faPending
	if ok, err := r.faTake(faPendingPrefix+id, &p); !ok || err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *Router) faNewCode(c faCode) (string, error) {
	code, err := faRandomID()
	if err != nil {
		return "", err
	}
	return code, r.faPut(faCodePrefix+code, c, faCodeTTL)
}

func (r *Router) faTakeCode(code string) (*faCode, error) {
	if code == "" {
		return nil, nil
	}
	var c faCode
	if ok, err := r.faTake(faCodePrefix+code, &c); !ok || err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *Router) faLoadIndex(username string) []faUserEntry {
	raw, err := r.storage.Get(faUserPrefix + username)
	if err != nil || raw == nil {
		return nil
	}
	var idx []faUserEntry
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil
	}
	return idx
}

func (r *Router) faSaveIndex(username string, idx []faUserEntry) error {
	if len(idx) == 0 {
		return r.storage.Delete(faUserPrefix + username)
	}
	// every indexed session expires within SessionMax of the newest one
	return r.faPut(faUserPrefix+username, idx, r.forwardAuth.SessionMax)
}

func (r *Router) faExists(id string) bool {
	raw, err := r.storage.Get(faSessPrefix + id)
	return err == nil && raw != nil
}

// faSave writes s with the time it has left until SessionMax
func (r *Router) faSave(s *faSession) error {
	left := time.Until(s.Created.Add(r.forwardAuth.SessionMax))
	if left <= 0 {
		return r.storage.Delete(faSessPrefix + s.ID)
	}
	return r.faPut(faSessPrefix+s.ID, s, left)
}

// faCreateSession fails rather than create a session that revocation could
// not find through the user index
func (r *Router) faCreateSession(s *faSession) error {
	id, err := faRandomID()
	if err != nil {
		return err
	}
	release, err := r.lock.holdStrict(faUserPrefix + s.Username)
	if err != nil {
		return err
	}
	defer release()

	now := time.Now()
	s.ID, s.Created, s.LastSeen, s.CheckedAt = id, now, now, now
	idx := []faUserEntry{{ID: id, ParentSID: s.ParentSID}}
	for _, e := range r.faLoadIndex(s.Username) {
		if r.faExists(e.ID) {
			idx = append(idx, e)
		}
	}
	if err := r.faSaveIndex(s.Username, idx); err != nil {
		return err
	}
	return r.faSave(s)
}

// faLoadSession returns nil for a missing, idle or expired session
func (r *Router) faLoadSession(id string) (*faSession, error) {
	if id == "" {
		return nil, nil
	}
	raw, err := r.storage.Get(faSessPrefix + id)
	if err != nil || raw == nil {
		return nil, err
	}
	var s faSession
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	now := time.Now()
	if now.Sub(s.LastSeen) > r.forwardAuth.SessionIdle || now.Sub(s.Created) > r.forwardAuth.SessionMax {
		return nil, r.faDeleteSession(id)
	}
	return &s, nil
}

// faTouch persists LastSeen at most once a minute, and a recheck
// (CheckedAt after LastSeen) right away
func (r *Router) faTouch(s *faSession) error {
	now := time.Now()
	if now.Sub(s.LastSeen) < faTouchEvery && !s.CheckedAt.After(s.LastSeen) {
		return nil
	}
	release, err := r.lock.holdStrict(faUserPrefix + s.Username)
	if err != nil {
		return err
	}
	defer release()
	// a revocation since the load deleted the session: writing it back
	// would leave a live session missing from the index
	if !r.faExists(s.ID) {
		return nil
	}
	s.LastSeen = now
	return r.faSave(s)
}

func (r *Router) faDeleteSession(id string) error {
	return r.storage.Delete(faSessPrefix + id)
}

// faRevoke deletes the user's app sessions whose parent mokey session
// matches. Without the lock it still deletes, and only skips the index
// rewrite: a stale index entry is harmless, a surviving session is not.
func (r *Router) faRevoke(username string, match func(parentSID string) bool) {
	if r.forwardAuth == nil {
		return
	}
	release, err := r.lock.holdStrict(faUserPrefix + username)
	if err != nil {
		slog.Warn("Revoking app sessions without storage lock",
			"username", username,
			"err", err,
		)
	} else {
		defer release()
	}

	idx := r.faLoadIndex(username)
	kept := idx[:0]
	for _, e := range idx {
		if !match(e.ParentSID) {
			kept = append(kept, e)
			continue
		}
		if derr := r.faDeleteSession(e.ID); derr != nil {
			slog.Error("Failed to revoke app session",
				"username", username,
				"err", derr,
			)
			kept = append(kept, e)
		}
	}
	if err != nil || len(kept) == len(idx) {
		return
	}
	if err := r.faSaveIndex(username, kept); err != nil {
		slog.Error("Failed to save app session index",
			"username", username,
			"err", err,
		)
	}
}

func (r *Router) faRevokeUser(username string) {
	r.faRevoke(username, func(string) bool { return true })
}

func (r *Router) faRevokeParent(username, parentSID string) {
	r.faRevoke(username, func(p string) bool { return p == parentSID })
}

func (r *Router) faRevokeOtherParents(username, keepSID string) {
	r.faRevoke(username, func(p string) bool { return p != keepSID })
}
