package server

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

// securityVars fills the Security page sections: sessions, activity, and
// (when Hydra is configured) connected apps. Shared by the HTMX partial
// render and the non-HTMX full-page Index render.
func (r *Router) securityVars(c fiber.Ctx, vars fiber.Map) {
	user := r.user(c)
	vars["user"] = user

	if sess, err := r.session(c); err == nil {
		vars["sessions"] = r.userSessions(user.Username, sess.ID())
	}
	vars["activity"] = auditUserRecent(r.storage, user.Username, 15)

	if r.hydraClient != nil {
		apps, err := r.listConnectedApps(user.Username)
		if err != nil {
			slog.Error("Failed to list connected apps",
				"username", user.Username,
				"err", err,
			)
			vars["apps_error"] = true
		} else {
			vars["connected_apps"] = apps
		}
	}
}

func (r *Router) securityList(c fiber.Ctx, vars fiber.Map) error {
	r.securityVars(c, vars)
	return c.Render("security.html", vars)
}

func (r *Router) SecurityList(c fiber.Ctx) error {
	return r.securityList(c, fiber.Map{})
}

// AppRevoke revokes the caller's consent for one connected OAuth client.
func (r *Router) AppRevoke(c fiber.Ctx) error {
	vars := fiber.Map{}
	user := r.user(c)
	clientID := c.FormValue("client")

	if err := r.revokeConnectedApp(user.Username, clientID); err != nil {
		slog.Error("Failed to revoke connected app",
			"username", user.Username,
			"client", clientID,
			"err", err,
		)
		vars["message"] = TC(c, "security.apps_revoke_failed")
	} else {
		slog.Info("AUDIT User revoked app access",
			"username", user.Username,
			"client", clientID,
			"ip", RemoteIP(c),
		)
	}

	return r.securityList(c, vars)
}

func (r *Router) TwoFactorDisable(c fiber.Ctx) error {
	vars := fiber.Map{}
	user := r.user(c)

	err := r.adminClient.SetAuthTypes(user.Username, nil)
	if err != nil {
		slog.Error("Failed to disable Two-Factor auth",
			"username", user.Username,
			"err", err,
		)
		vars["message"] = "Failed to disable Two-Factor authentication"
	}

	user.AuthTypes = nil
	c.Locals(ContextKeyUser, user)

	err = r.emailer.SendMFAChangedEmail(false, user, c)
	if err != nil {
		slog.Error("Failed to send mfa disabled email",
			"err", err,
			"username", user.Username,
		)
	}

	return r.securityList(c, vars)
}

func (r *Router) TwoFactorEnable(c fiber.Ctx) error {
	client := r.userClient(c)
	vars := fiber.Map{}
	user := r.user(c)

	tokens, err := client.FetchOTPTokens(user.Username)
	if err != nil {
		slog.Error("Failed to check otp tokens",
			"username", user.Username,
			"err", err,
		)
		vars["message"] = "Failed to enable Two-Factor authentication"
		return r.securityList(c, vars)
	}

	if len(tokens) == 0 {
		vars["message"] = "You must add an OTP token first before enabling Two-Factor authentication"
		return r.securityList(c, vars)
	}

	otpOnly := []string{"otp"}
	err = r.adminClient.SetAuthTypes(user.Username, otpOnly)
	if err != nil {
		slog.Error("Failed to enable Two-Factor auth",
			"username", user.Username,
			"err", err,
		)
		vars["message"] = "Failed to enable Two-Factor authentication"
	}

	user.AuthTypes = otpOnly
	c.Locals(ContextKeyUser, user)

	err = r.emailer.SendMFAChangedEmail(true, user, c)
	if err != nil {
		slog.Error("Failed to send mfa enabled email",
			"err", err,
			"username", user.Username,
		)
	}

	return r.securityList(c, vars)
}
