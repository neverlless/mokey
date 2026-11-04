package server

import (
	"bytes"
	"encoding/gob"
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
)

func (r *Router) session(c fiber.Ctx) (*session.Session, error) {
	sess, err := r.sessionStore.Get(c)
	if err != nil && r.migrateFiberV2Session(c) {
		sess, err = r.sessionStore.Get(c)
	}
	if err != nil {
		slog.Error("Failed to fetch session from storage",
			"path", c.Path(),
			"err", err,
		)
		return nil, err
	}

	return sess, nil
}

// migrateFiberV2Session rewrites session data saved before the move to
// Fiber v3, which encoded it as map[string]interface{} where v3 decodes
// map[any]any. Without it every request on a session kept in redis or
// sqlite3 across the upgrade fails until the session expires.
func (r *Router) migrateFiberV2Session(c fiber.Ctx) bool {
	id := c.Cookies("session_id")
	if id == "" {
		return false
	}
	raw, err := r.storage.Get(id)
	if err != nil || raw == nil {
		return false
	}

	var old map[string]interface{}
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&old); err != nil {
		return false
	}
	data := make(map[any]any, len(old))
	for k, v := range old {
		data[k] = v
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&data); err != nil {
		return false
	}
	return r.storage.Set(id, buf.Bytes(), r.sessionStore.IdleTimeout) == nil
}

func (r *Router) sessionSave(c fiber.Ctx, sess *session.Session) error {
	if err := sess.Save(); err != nil {
		slog.Error("Failed to save session to storage",
			"path", c.Path(),
			"err", err,
		)

		return err
	}

	return nil
}
