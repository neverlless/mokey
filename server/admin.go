// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"errors"
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

const adminUserListLimit = 50

// adminUserVars builds the template vars for the admin user table.
// ponytail: fetches up to 500 users and filters substring in Go — fine for
// typical directories; server-side criteria search if this becomes slow.
func (r *Router) adminUserVars(c *fiber.Ctx, search string) fiber.Map {
	vars := fiber.Map{
		"user":   r.user(c),
		"search": search,
	}

	users, err := r.adminClient.UserFind(ipa.Options{"sizelimit": 500})
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Failed to list users from FreeIPA")
		vars["users_message"] = T("account.fatal_system_error")
		return vars
	}

	needle := strings.ToLower(strings.TrimSpace(search))
	matched := make([]*ipa.User, 0, len(users))
	for _, u := range users {
		if needle == "" ||
			strings.Contains(strings.ToLower(u.Username), needle) ||
			strings.Contains(strings.ToLower(u.Email), needle) ||
			strings.Contains(strings.ToLower(u.First+" "+u.Last), needle) {
			matched = append(matched, u)
		}
	}

	vars["total"] = len(matched)
	if len(matched) > adminUserListLimit {
		matched = matched[:adminUserListLimit]
	}
	vars["users"] = matched

	return vars
}

func (r *Router) AdminUserList(c *fiber.Ctx) error {
	return c.Render("admin-users.html", r.adminUserVars(c, c.Query("search")))
}

func (r *Router) AdminUserAction(c *fiber.Ctx) error {
	username := strings.TrimSpace(c.FormValue("username"))
	action := c.Params("action")
	search := c.FormValue("search")

	if username == "" {
		return c.Status(fiber.StatusBadRequest).SendString("")
	}

	if username == r.username(c) && action != "reset" {
		return c.Status(fiber.StatusBadRequest).SendString(T("admin.cannot_block_self"))
	}

	var err error
	switch action {
	case "block":
		err = r.adminClient.UserDisable(username)
	case "unblock":
		err = r.adminClient.UserEnable(username)
	case "reset":
		var target *ipa.User
		target, err = r.adminClient.UserShow(username)
		if err == nil {
			err = r.emailer.SendPasswordResetEmail(target, c)
		}
	case "unlock":
		err = userUnlock(r.adminClient, username)
	case "approve":
		// staged signups live in the staging tree; legacy pending users
		// (from before staged_signup) are handled below
		var staged *ipa.User
		if viper.GetBool("accounts.staged_signup") {
			staged, _ = stageUserShow(r.adminClient, username)
		}
		if staged != nil {
			if staged.Category != UserCategoryPending {
				err = errors.New("user is not pending approval")
				break
			}
			// clear the pending marker before activation copies it over
			err = stageUserSetCategory(r.adminClient, username, "")
			if err == nil {
				err = stageUserActivate(r.adminClient, username)
			}
			if err == nil {
				staged.Category = ""
				if werr := r.emailer.SendWelcomeEmail(staged, c); werr != nil {
					log.WithFields(log.Fields{
						"username": username,
						"err":      werr,
					}).Error("Failed to send welcome email to approved user")
				}
			}
			break
		}
		var target *ipa.User
		target, err = r.adminClient.UserShow(username)
		if err == nil && target.Category != UserCategoryPending {
			err = errors.New("user is not pending approval")
		}
		if err == nil {
			err = r.adminClient.UserEnable(username)
		}
		if err == nil {
			target.Category = ""
			_, err = r.adminClient.UserMod(target)
		}
		if err == nil {
			if werr := r.emailer.SendWelcomeEmail(target, c); werr != nil {
				log.WithFields(log.Fields{
					"username": username,
					"err":      werr,
				}).Error("Failed to send welcome email to approved user")
			}
		}
	case "deny":
		var staged *ipa.User
		if viper.GetBool("accounts.staged_signup") {
			staged, _ = stageUserShow(r.adminClient, username)
		}
		if staged != nil {
			if staged.Category != UserCategoryPending {
				err = errors.New("user is not pending approval")
				break
			}
			err = stageUserDel(r.adminClient, username)
			break
		}
		var target *ipa.User
		target, err = r.adminClient.UserShow(username)
		if err == nil && target.Category != UserCategoryPending {
			err = errors.New("user is not pending approval")
		}
		if err == nil {
			err = r.adminClient.UserDelete(false, true, username)
		}
	case "otprecovery-approve":
		queued := false
		for _, req := range r.loadOTPRecoveryRequests() {
			if req.Username == username {
				queued = true
				break
			}
		}
		if !queued {
			err = errors.New("no pending OTP recovery request")
			break
		}
		err = r.adminClient.SetAuthTypes(username, []string{"password"})
		if err == nil {
			r.removeOTPRecoveryRequest(username)
			r.sendOTPRecoveryDecision(username, true)
		}
	case "otprecovery-deny":
		if !r.removeOTPRecoveryRequest(username) {
			err = errors.New("no pending OTP recovery request")
			break
		}
		r.sendOTPRecoveryDecision(username, false)
	default:
		return c.Status(fiber.StatusBadRequest).SendString("")
	}

	// already enabled (4009) / already disabled (4010) — treat as success
	if ierr, ok := err.(*ipa.IpaError); ok && (ierr.Code == 4009 || ierr.Code == 4010) {
		err = nil
	}

	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": username,
			"action":   action,
			"admin":    r.username(c),
		}).Error("Admin user action failed")
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	log.WithFields(log.Fields{
		"username": username,
		"action":   action,
		"admin":    r.username(c),
		"ip":       RemoteIP(c),
	}).Info("AUDIT admin user action")

	// approve/deny buttons live in the pending queue; re-render it
	if action == "approve" || action == "deny" {
		return r.AdminPendingList(c)
	}
	// otprecovery approve/deny buttons live in the recovery queue
	if action == "otprecovery-approve" || action == "otprecovery-deny" {
		return r.AdminOTPRecoveryList(c)
	}

	vars := r.adminUserVars(c, search)
	if action == "reset" {
		vars["reset_sent"] = username
	}
	return c.Render("admin-users.html", vars)
}

// AdminPendingList renders signups that confirmed their email and now wait
// for admin approval (require_admin_verify)
func (r *Router) AdminPendingList(c *fiber.Ctx) error {
	users, err := r.adminClient.UserFind(ipa.Options{
		"userclass": UserCategoryPending,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Failed to list pending users")
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	// user_find matches loosely; keep only exact pending accounts
	pending := []*ipa.User{}

	// staged signups awaiting approval live in the staging tree; legacy
	// pending users below still surface during a backend transition
	if viper.GetBool("accounts.staged_signup") {
		staged, serr := stageUserFindPending(r.adminClient)
		if serr != nil {
			log.WithFields(log.Fields{
				"err": serr,
			}).Error("Failed to list pending staged users")
		} else {
			pending = append(pending, staged...)
		}
	}
	for _, u := range users {
		if u.Category == UserCategoryPending {
			pending = append(pending, u)
		}
	}

	return c.Render("admin-pending.html", fiber.Map{
		"user":    r.user(c),
		"pending": pending,
	})
}

// otpRecoveryView pairs a queued request's user with its RequestedAt for
// the admin-otprecovery.html table.
type otpRecoveryView struct {
	User        *ipa.User
	RequestedAt time.Time
}

// AdminOTPRecoveryList renders the OTP recovery queue for admin review.
// Always visible (unlike the pending-signup queue, which is gated by
// accounts.require_admin_verify).
func (r *Router) AdminOTPRecoveryList(c *fiber.Ctx) error {
	requests := []otpRecoveryView{}
	for _, req := range r.loadOTPRecoveryRequests() {
		user, err := r.adminClient.UserShow(req.Username)
		if err != nil || !user.OTPOnly() {
			// stale: user gone, or no longer OTP-only (recovered through
			// another path) — drop, mirroring stale group request cleanup
			r.removeOTPRecoveryRequest(req.Username)
			continue
		}
		requests = append(requests, otpRecoveryView{User: user, RequestedAt: req.RequestedAt})
	}

	return c.Render("admin-otprecovery.html", fiber.Map{
		"user":     r.user(c),
		"requests": requests,
	})
}

// sendOTPRecoveryDecision emails the requester about the outcome (fire and log)
func (r *Router) sendOTPRecoveryDecision(username string, approved bool) {
	target, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{"username": username, "err": err}).Error("Failed to fetch requester for OTP recovery decision email")
		return
	}
	if err := r.emailer.SendOTPRecoveryDecisionEmail(target, approved); err != nil {
		log.WithFields(log.Fields{"username": username, "err": err}).Error("Failed to send OTP recovery decision email")
	}
}

func (r *Router) AdminAuditList(c *fiber.Ctx) error {
	return c.Render("admin-audit.html", fiber.Map{
		"user":   r.user(c),
		"events": auditRecent(r.storage, 50),
	})
}
