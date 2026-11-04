package server

import (
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

func (r *Router) session(c *fiber.Ctx) (*session.Session, error) {
	sess, err := r.sessionStore.Get(c)
	if err != nil {
		slog.Error("Failed to fetch session from storage",
			"path", c.Path(),
			"err", err,
		)
		return nil, err
	}

	return sess, nil
}

func (r *Router) sessionSave(c *fiber.Ctx, sess *session.Session) error {
	if err := sess.Save(); err != nil {
		slog.Error("Failed to save session to storage",
			"path", c.Path(),
			"err", err,
		)

		return err
	}

	return nil
}
