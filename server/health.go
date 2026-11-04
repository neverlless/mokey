package server

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

// Healthz is an unauthenticated health check endpoint. It verifies the
// session storage backend and FreeIPA are reachable. Registered before the
// CSRF middleware so probes don't create sessions.
func (r *Router) Healthz(c fiber.Ctx) error {
	if _, err := r.storage.Get("healthz"); err != nil {
		slog.Error("healthz: session storage check failed",
			"error", err,
		)
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status":  "unavailable",
			"storage": err.Error(),
		})
	}

	if _, err := r.adminClient.Ping(); err != nil {
		slog.Error("healthz: FreeIPA ping failed",
			"error", err,
		)
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status":  "unavailable",
			"freeipa": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"status": "ok",
	})
}
