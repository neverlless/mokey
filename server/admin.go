// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

// isAdmin reports whether the user may access the admin panel: member of
// the configured FreeIPA group (default "admins") or explicitly listed in
// admin.users. Enforced server-side on every admin route via RequireAdmin.
func isAdmin(user *ipa.User) bool {
	if !viper.GetBool("admin.enabled") {
		return false
	}

	group := viper.GetString("admin.group")
	for _, g := range user.Groups {
		if g == group {
			return true
		}
	}

	for _, u := range viper.GetStringSlice("admin.users") {
		if u == user.Username {
			return true
		}
	}

	return false
}

func (r *Router) RequireAdmin(c *fiber.Ctx) error {
	if !isAdmin(r.user(c)) {
		log.WithFields(log.Fields{
			"username": r.username(c),
			"path":     c.Path(),
			"ip":       RemoteIP(c),
		}).Warn("AUDIT non-admin user attempted to access admin route")
		return c.Status(fiber.StatusForbidden).SendString("")
	}

	return c.Next()
}

// InviteSend handles the admin invite form. An invite token is emailed to
// the address; the invited user completes their own profile via
// InviteAccept. Works regardless of accounts.enable_signup.
func (r *Router) InviteSend(c *fiber.Ctx) error {
	email := strings.TrimSpace(strings.ToLower(c.FormValue("email")))

	vars := fiber.Map{
		"user": r.user(c),
	}

	check := &ipa.User{Email: email}
	if err := validateEmail(check, viper.GetStringMapString("accounts.allowed_domains")); err != nil {
		vars["message"] = T("account.email_invalid")
		return c.Render("admin.html", vars)
	}

	if err := r.emailer.SendInviteEmail(email, c); err != nil {
		log.WithFields(log.Fields{
			"email": email,
			"err":   err,
		}).Error("Failed to send invite email")
		vars["message"] = T("account.fatal_system_error")
		return c.Render("admin.html", vars)
	}

	log.WithFields(log.Fields{
		"email":      email,
		"invited_by": r.username(c),
		"ip":         RemoteIP(c),
	}).Info("AUDIT user invite sent")

	vars["invite_sent"] = email
	return c.Render("admin.html", vars)
}

// InviteAccept lets an invited user complete their own account. The token
// proves ownership of the invited email address, so the account is created
// enabled with no further email verification.
func (r *Router) InviteAccept(c *fiber.Ctx) error {
	token := c.Params("token")

	claims, err := ParseToken(token, TokenInvite, r.storage)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Debug("Invalid invite token")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("invite.html", fiber.Map{
			"claims":            claims,
			"usernameFromEmail": viper.GetBool("accounts.username_from_email"),
		})
	}

	user := &ipa.User{}
	user.Username = strings.TrimSpace(c.FormValue("username"))
	user.Email = claims.Email
	user.First = strings.TrimSpace(c.FormValue("first"))
	user.Last = strings.TrimSpace(c.FormValue("last"))

	if err := r.accountCreate(user, c.FormValue("password"), c.FormValue("password2"), true); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	r.storage.Set(TokenInvite+TokenUsedPrefix+token, []byte("true"), time.Until(claims.Timestamp.Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second)))

	log.WithFields(log.Fields{
		"username": user.Username,
		"email":    user.Email,
		"ip":       RemoteIP(c),
	}).Info("AUDIT invited user account created successfully")
	r.metrics.totalSignups.Inc()

	if err := r.emailer.SendWelcomeEmail(user, c); err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
		}).Error("Failed to send welcome email to invited user")
	}

	return c.Render("signup-success.html", fiber.Map{
		"user":    user,
		"invited": true,
	})
}
