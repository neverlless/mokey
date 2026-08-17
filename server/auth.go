package server

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

func isBlocked(username string) bool {
	blockUsers := viper.GetStringSlice("accounts.block_users")
	for _, u := range blockUsers {
		if username == u {
			return true
		}
	}

	return false
}

func (r *Router) isLoggedIn(c *fiber.Ctx) (bool, error) {
	sess, err := r.session(c)
	if err != nil {
		return false, errors.New("Failed to get session")
	}

	username := sess.Get(SessionKeyUsername)
	sid := sess.Get(SessionKeySID)
	authenticated := sess.Get(SessionKeyAuthenticated)
	if sid == nil || username == nil || authenticated == nil {
		return false, errors.New("Invalid session")
	}

	if _, ok := username.(string); !ok {
		return false, errors.New("Invalid user in session")
	}

	if _, ok := sid.(string); !ok {
		return false, errors.New("Invalid sid in session")
	}

	if isAuthed, ok := authenticated.(bool); !ok || !isAuthed {
		return false, errors.New("User is not authenticated in session")
	}

	// Sessions established before the user's last password change are
	// invalid. ponytail: 1-second resolution — a session created within
	// the same second as the change survives; sessions carrying no
	// login_time (pre-upgrade) are treated as older than any marker.
	marker, _ := r.storage.Get(PasswordChangedPrefix + username.(string))
	loginTime, _ := sess.Get(SessionKeyLoginTime).(int64)
	if sessionInvalidatedByPasswordChange(loginTime, marker) {
		return false, errors.New("Session invalidated by password change")
	}

	client := newIPAClientWithSession(sid.(string))
	user, err := client.UserShow(username.(string))
	if err != nil {
		return false, fmt.Errorf("Failed to refresh FreeIPA user session: %w", err)
	}

	c.Locals(ContextKeyUsername, username)
	c.Locals(ContextKeyUser, user)
	c.Locals(ContextKeyIPAClient, client)

	// Update session expiry time
	sess.SetExpiry(time.Duration(viper.GetInt("server.session_idle_timeout")) * time.Second)

	sess.Save()

	return true, nil
}

// invalidateUserSessions marks all of username's existing sessions invalid
// via a password-change marker checked in isLoggedIn. A caller that wants
// its own session to survive must set SessionKeyLoginTime to time.Now()
// after calling this. Marker TTL slightly exceeds the session idle timeout:
// any older session either hits the marker on its next request or expires.
func sessionInvalidatedByPasswordChange(loginTime int64, marker []byte) bool {
	if marker == nil {
		return false
	}
	changedAt, err := strconv.ParseInt(string(marker), 10, 64)
	if err != nil {
		return false
	}
	return loginTime < changedAt
}

func (r *Router) invalidateUserSessions(username string) {
	ttl := time.Duration(viper.GetInt("server.session_idle_timeout"))*time.Second + time.Minute
	r.storage.Set(PasswordChangedPrefix+username, []byte(strconv.FormatInt(time.Now().Unix(), 10)), ttl)
}

func (r *Router) Login(c *fiber.Ctx) error {
	vars := fiber.Map{}
	return c.Render("login.html", vars)
}

func (r *Router) Logout(c *fiber.Ctx) error {
	if viper.IsSet("hydra.admin_url") && c.Query("logout_challenge") != "" {
		return r.HydraLogout(c)
	}

	// The GET route exists only for Hydra's front-channel logout. GETs skip
	// CSRF, so without a challenge they must not destroy the session — a
	// third-party page could force-logout users otherwise
	if c.Method() == fiber.MethodGet {
		return c.Redirect("/auth/login")
	}

	return r.redirectLogin(c)
}

func (r *Router) logout(c *fiber.Ctx) {
	sess, err := r.session(c)
	if err != nil {
		return
	}

	username := sess.Get(SessionKeyUsername)
	if username != nil {
		log.WithFields(log.Fields{
			"username": username,
			"ip":       RemoteIP(c),
			"path":     c.Path(),
		}).Info("User logging out")
	}

	if err := sess.Destroy(); err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"ip":       RemoteIP(c),
			"path":     c.Path(),
			"err":      err,
		}).Error("Logout failed to destroy session")
	}

	if viper.IsSet("hydra.admin_url") {
		if _, ok := username.(string); ok {
			err := r.revokeHydraAuthenticationSession(username.(string))
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
				}).Error("Logout failed to revoke hydra authentication session")
			}
		}
	}
}

func (r *Router) redirectLogin(c *fiber.Ctx) error {
	r.logout(c)

	if c.Get("HX-Request", "false") == "true" {
		c.Set("HX-Redirect", "/auth/login")
		return c.Status(fiber.StatusNoContent).SendString("")
	}

	return c.Redirect("/auth/login")
}

func (r *Router) RequireNoLogin(c *fiber.Ctx) error {
	if ok, _ := r.isLoggedIn(c); ok {
		if c.Get("HX-Request", "false") == "true" {
			c.Set("HX-Redirect", "/")
			return c.Status(fiber.StatusNoContent).SendString("")
		}

		return c.Redirect("/")
	}

	return c.Next()
}

func (r *Router) RequireLogin(c *fiber.Ctx) error {
	if ok, err := r.isLoggedIn(c); !ok {
		log.WithFields(log.Fields{
			"path":  c.Path(),
			"ip":    RemoteIP(c),
			"error": err,
		}).Info("Login required and no authenticated session found.")
		return r.redirectLogin(c)
	}

	return c.Next()
}

func (r *Router) RequireMFA(c *fiber.Ctx) error {
	if !viper.GetBool("accounts.require_mfa") {
		return c.Next()
	}

	user := r.user(c)
	if !user.OTPOnly() {
		return c.Status(fiber.StatusUnauthorized).SendString(T("account.you_must_enable_two_factor_authentication_first"))
	}

	return c.Next()
}

func (r *Router) CheckUser(c *fiber.Ctx) error {
	username := c.FormValue("username")

	if username == "" {
		return c.Status(fiber.StatusBadRequest).SendString(T("account.please_provide_username"))
	}

	if isBlocked(username) {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT User account is blocked from logging in")
		r.metrics.totalFailedLogins.Inc()
		// With hidden username errors, show the password form anyway —
		// Authenticate rejects blocked users with the generic message
		if !viper.GetBool("accounts.hide_invalid_username_error") {
			return c.Status(fiber.StatusUnauthorized).SendString(T("account.invalid_username"))
		}
		userRec := new(ipa.User)
		userRec.Username = username
		return c.Render("login-form.html", fiber.Map{
			"user":      userRec,
			"challenge": c.FormValue("challenge"),
		})
	}

	userRec, err := r.adminClient.UserShow(username)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4001 {
			log.WithFields(log.Fields{
				"error":    ierr,
				"username": username,
			}).Warn("Username not found in FreeIPA")

			if !viper.GetBool("accounts.hide_invalid_username_error") {
				r.metrics.totalFailedLogins.Inc()
				return c.Status(fiber.StatusUnauthorized).SendString(T("account.invalid_username"))
			}
			userRec = new(ipa.User)
			userRec.Username = username
		} else {
			log.WithFields(log.Fields{
				"error":    err,
				"username": username,
			}).Error("Failed to fetch user info from FreeIPA")
			r.metrics.totalFailedLogins.Inc()
			return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
		}
	}

	if userRec.Locked {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT User account is locked in FreeIPA")
		r.metrics.totalFailedLogins.Inc()
		// With hidden username errors, the locked state must not be
		// distinguishable either — FreeIPA rejects the login attempt with
		// the same error as a bad password
		if !viper.GetBool("accounts.hide_invalid_username_error") {
			return c.Status(fiber.StatusUnauthorized).SendString(T("account.user_account_is_locked"))
		}
	}

	log.WithFields(log.Fields{
		"username": username,
		"ip":       RemoteIP(c),
	}).Info("Login user attempt")

	vars := fiber.Map{
		"user":      userRec,
		"challenge": c.FormValue("challenge"),
	}

	return c.Render("login-form.html", vars)
}

func (r *Router) Authenticate(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	challenge := c.FormValue("challenge")
	otp := c.FormValue("otp")

	if username == "" {
		return c.Status(fiber.StatusBadRequest).SendString(T("account.please_provide_username"))
	}

	if password == "" {
		return c.Status(fiber.StatusBadRequest).SendString(T("account.please_provide_password"))
	}

	if isBlocked(username) {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT User account is blocked from logging in")
		r.metrics.totalFailedLogins.Inc()
		return c.Status(fiber.StatusUnauthorized).SendString(T("account.invalid_credentials"))
	}

	client := newIPAClient()
	err := client.RemoteLogin(username, password+otp)
	if err != nil {
		switch {
		case errors.Is(err, ipa.ErrExpiredPassword):
			log.WithFields(log.Fields{
				"username": username,
				"err":      err,
			}).Info("Password expired, forcing change")

			sess, err := r.session(c)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString("")
			}

			err = sess.Regenerate()
			if err != nil {
				return err
			}

			sess.Set(SessionKeyAuthenticated, false)
			sess.Set(SessionKeyUsername, username)

			if err := r.sessionSave(c, sess); err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString("")
			}

			userRec, err := r.adminClient.UserShow(username)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString("")
			}

			vars := fiber.Map{
				"username": username,
				"user":     userRec,
			}
			return c.Render("login-password-expired.html", vars)
		default:
			log.WithFields(log.Fields{
				"username": username,
				"ip":       RemoteIP(c),
				"err":      err,
			}).Error("AUDIT Failed login attempt")
			r.metrics.totalFailedLogins.Inc()
			return c.Status(fiber.StatusUnauthorized).SendString(T("account.invalid_credentials"))
		}
	}

	_, err = client.Ping()
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Error("Failed to ping FreeIPA")
		r.metrics.totalFailedLogins.Inc()
		return c.Status(fiber.StatusUnauthorized).SendString(T("account.invalid_credentials"))
	}

	sess, err := r.session(c)
	if err != nil {
		return err
	}

	err = sess.Regenerate()
	if err != nil {
		return err
	}

	sess.Set(SessionKeyAuthenticated, true)
	sess.Set(SessionKeyUsername, username)
	sess.Set(SessionKeySID, client.SessionID())
	sess.Set(SessionKeyLoginTime, time.Now().Unix())

	if err := r.sessionSave(c, sess); err != nil {
		return err
	}

	if viper.IsSet("hydra.admin_url") && challenge != "" {
		return r.LoginOAuthPost(username, challenge, c)
	}

	log.WithFields(log.Fields{
		"username": username,
		"ip":       RemoteIP(c),
	}).Info("AUDIT User logged in successfully")
	r.metrics.totalLogins.Inc()

	c.Set("HX-Redirect", "/")
	return c.Status(fiber.StatusNoContent).SendString("")
}
