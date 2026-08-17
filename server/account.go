package server

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

func (r *Router) AccountSettings(c *fiber.Ctx) error {
	user := r.user(c)

	vars := fiber.Map{
		"user": user,
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("account.html", vars)
	}

	user.First = strings.TrimSpace(c.FormValue("first"))
	user.Last = strings.TrimSpace(c.FormValue("last"))
	user.Mobile = strings.TrimSpace(c.FormValue("phone"))
	user.DisplayName = strings.TrimSpace(c.FormValue("displayname"))
	user.TelephoneNumber = strings.TrimSpace(c.FormValue("telephone"))

	// Shell changes are opt-in and restricted to the configured allowlist
	if viper.GetBool("accounts.allow_change_shell") {
		shell := strings.TrimSpace(c.FormValue("shell"))
		for _, allowed := range viper.GetStringSlice("accounts.allowed_shells") {
			if shell == allowed {
				user.Shell = shell
				break
			}
		}
	}

	if user.First == "" || user.Last == "" {
		vars["message"] = "Please provide a first and last name"
		return c.Render("account.html", vars)
	}

	if len(user.First) > 150 || len(user.Last) > 150 {
		vars["message"] = "First or Last name is too long. Maximum of 150 chars allowed"
		return c.Render("account.html", vars)
	}

	// Email changes are not applied directly: a confirmation link is sent
	// to the new address and the change happens in EmailChangeConfirm
	newEmail := strings.TrimSpace(strings.ToLower(c.FormValue("email")))
	emailChangeRequested := newEmail != "" && !strings.EqualFold(newEmail, user.Email)
	if emailChangeRequested {
		check := &ipa.User{Email: newEmail}
		if err := validateEmail(check, viper.GetStringMapString("accounts.allowed_domains")); err != nil {
			vars["message"] = T("account.email_invalid")
			return c.Render("account.html", vars)
		}
	}

	userUpdated, err := r.adminClient.UserMod(user)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			log.WithFields(log.Fields{
				"username": user.Username,
				"message":  ierr.Message,
				"code":     ierr.Code,
			}).Error("Failed to update account settings")
			vars["message"] = "Failed to save account settings"
		} else {
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err.Error(),
			}).Error("Failed to update account settings")
			vars["message"] = T("account.fatal_system_error")
		}
	} else {
		vars["user"] = userUpdated
		vars["success"] = true

		if emailChangeRequested {
			if err := r.emailer.SendEmailChangeConfirmEmail(user, newEmail, c); err != nil {
				log.WithFields(log.Fields{
					"username": user.Username,
					"email":    newEmail,
					"err":      err,
				}).Error("Failed to send email change confirmation email")
				vars["message"] = T("account.fatal_system_error")
			} else {
				log.WithFields(log.Fields{
					"username":  user.Username,
					"new_email": newEmail,
					"ip":        RemoteIP(c),
				}).Info("AUDIT email change requested")
				vars["email_change_sent"] = true
			}
		}
	}
	return c.Render("account.html", vars)
}

func (r *Router) AccountCreate(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"captchaID":         newCaptchaID(),
			"usernameFromEmail": viper.GetBool("accounts.username_from_email"),
		}

		return c.Render("signup.html", vars)
	}

	user := &ipa.User{}
	user.Username = strings.TrimSpace(c.FormValue("username"))
	user.Email = strings.TrimSpace(c.FormValue("email"))
	user.First = strings.TrimSpace(c.FormValue("first"))
	user.Last = strings.TrimSpace(c.FormValue("last"))
	password := c.FormValue("password")
	passwordConfirm := c.FormValue("password2")
	captchaID := c.FormValue("captcha_id")
	captchaSol := c.FormValue("captcha_sol")

	err := r.verifyCaptcha(captchaID, captchaSol)
	if err == nil {
		err = r.accountCreate(user, password, passwordConfirm, false)
	}
	if err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+captcha.New()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	log.WithFields(log.Fields{
		"username": user.Username,
		"email":    user.Email,
	}).Info("AUDIT user account created successfully")
	r.metrics.totalSignups.Inc()

	// Send user an email to verify their account
	err = r.emailer.SendAccountVerifyEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to send new account email")
	} else {
		log.WithFields(log.Fields{
			"username": user.Username,
			"email":    user.Email,
		}).Info("New user account email sent successfully")
		r.metrics.totalAccountVerificationsSent.Inc()
	}

	vars := fiber.Map{
		"user": user,
	}
	return c.Render("signup-success.html", vars)
}

// accountCreate does the work of validation and creating the account in
// FreeIPA. When verified is true (invited users whose email is already
// proven) the account is enabled immediately and skips email verification.
func (r *Router) accountCreate(user *ipa.User, password, passwordConfirm string, verified bool) error {
	if err := validateUsername(user); err != nil {
		return err
	}

	if user.First == "" || user.Last == "" {
		return errors.New("Please provide your first and last name")
	}

	if len(user.First) > 150 {
		return errors.New("First name is too long. Maximum of 150 chars allowed")
	}

	if len(user.Last) > 150 {
		return errors.New("Last name is too long. Maximum of 150 chars allowed")
	}

	if err := validatePassword(password, passwordConfirm); err != nil {
		return err
	}

	user.HomeDir = filepath.Join(viper.GetString("accounts.default_homedir"), user.Username)
	user.Shell = viper.GetString("accounts.default_shell")
	if !verified {
		user.Category = UserCategoryUnverified
	}

	userRec, err := r.adminClient.UserAddWithPassword(user, password)
	if err != nil {
		switch {
		case errors.Is(err, ipa.ErrUserExists):
			return fmt.Errorf("Username already exists: %s", user.Username)
		default:
			log.WithFields(log.Fields{
				"err":      err,
				"username": user.Username,
				"email":    user.Email,
				"first":    user.First,
				"last":     user.Last,
				"homedir":  user.HomeDir,
			}).Error("Failed to create user account")
			return errors.New("Failed to create account. Please contact system administrator")
		}
	}

	log.WithFields(log.Fields{
		"username": userRec.Username,
		"email":    userRec.Email,
		"first":    userRec.First,
		"last":     userRec.Last,
		"homedir":  userRec.HomeDir,
	}).Debug("New user account created")

	if verified {
		return nil
	}

	// Disable new users until they have verified their email address
	err = r.adminClient.UserDisable(userRec.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": userRec.Username,
		}).Error("Failed to disable user")

		// TODO: should we tell user about this? probably not?
	}

	return nil
}

func (r *Router) AccountVerify(c *fiber.Ctx) error {
	token := c.Params("token")

	claims, err := ParseToken(token, TokenAccountVerify, r.storage)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Debug("Invalid account verify token")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	vars := fiber.Map{
		"claims": claims,
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("verify-account.html", vars)
	}

	user, err := r.adminClient.UserShow(claims.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": claims.Username,
			"email":    claims.Email,
			"err":      err,
		}).Error("Verifying account failed while fetching user from FreeIPA")
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.failed_to_verify_account"))
	}

	if user.Locked && !viper.GetBool("accounts.require_admin_verify") {
		err := r.adminClient.UserEnable(claims.Username)
		if err != nil {
			log.WithFields(log.Fields{
				"username": claims.Username,
				"email":    claims.Email,
				"error":    err,
			}).Error("Verify account failed to enable user in FreeIPA")
			return c.Status(fiber.StatusInternalServerError).SendString(T("account.failed_to_verify_account"))
		}
	}

	// User is now verified so unset category
	if user.Category == UserCategoryUnverified {
		user.Category = ""

		_, err = r.adminClient.UserMod(user)
		if err != nil {
			log.WithFields(log.Fields{
				"username": claims.Username,
				"email":    claims.Email,
				"error":    err,
			}).Error("Verify account failed to modify user category in FreeIPA")
			return c.Status(fiber.StatusInternalServerError).SendString(T("account.failed_to_verify_account"))
		}
	}

	r.storage.Set(TokenAccountVerify+TokenUsedPrefix+token, []byte("true"), time.Until(claims.Timestamp.Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second)))

	err = r.emailer.SendWelcomeEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to send welcome email")
	}

	log.WithFields(log.Fields{
		"username": user.Username,
		"email":    user.Email,
	}).Info("AUDIT user account verified successfully")
	r.metrics.totalAccountVerifications.Inc()

	return c.Render("verify-success.html", vars)
}

func (r *Router) AccountVerifyResend(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"captchaID": newCaptchaID(),
		}

		return c.Render("account-verify-forgot.html", vars)
	}

	err := r.verifyCaptcha(c.FormValue("captcha_id"), c.FormValue("captcha_sol"))
	if err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+captcha.New()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	username := c.FormValue("username")

	if isBlocked(username) {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("Account verify resend attempt for blocked user")
		return c.Render("account-verify-forgot-success.html", fiber.Map{})
	}

	user, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Warn("Account verify resend attempt for unknown username")
		return c.Render("account-verify-forgot-success.html", fiber.Map{})
	}

	if !user.Locked && !viper.GetBool("accounts.require_admin_verify") {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("Account verify resend attempt for active user")
		return c.Render("account-verify-forgot-success.html", fiber.Map{})
	}

	if user.Category != UserCategoryUnverified {
		log.WithFields(log.Fields{
			"username": username,
		}).Warnf("Refusing to send account verify email. Invalid user category")
		return c.Render("account-verify-forgot-success.html", fiber.Map{})
	}

	// Resend user an email to verify their account
	err = r.emailer.SendAccountVerifyEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to re-send verify account email")
	} else {
		log.WithFields(log.Fields{
			"username": user.Username,
			"email":    user.Email,
		}).Info("Verify user account email sent successfully")
		r.metrics.totalAccountVerificationsSent.Inc()
	}

	return c.Render("account-verify-forgot-success.html", fiber.Map{})
}

// EmailChangeConfirm applies a pending email change. GET renders a
// confirmation page, POST performs the change.
func (r *Router) EmailChangeConfirm(c *fiber.Ctx) error {
	token := c.Params("token")

	claims, err := ParseToken(token, TokenEmailChange, r.storage)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Debug("Invalid email change token")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	vars := fiber.Map{
		"claims": claims,
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("email-change-confirm.html", vars)
	}

	user, err := r.adminClient.UserShow(claims.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": claims.Username,
			"email":    claims.Email,
			"err":      err,
		}).Error("Email change failed while fetching user from FreeIPA")
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	oldEmail := user.Email
	user.Email = claims.Email

	if _, err := r.adminClient.UserMod(user); err != nil {
		log.WithFields(log.Fields{
			"username": claims.Username,
			"email":    claims.Email,
			"err":      err,
		}).Error("Email change failed to modify user in FreeIPA")
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	r.storage.Set(TokenEmailChange+TokenUsedPrefix+token, []byte("true"), time.Until(claims.Timestamp.Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second)))

	if oldEmail != "" {
		if err := r.emailer.SendEmailChangedNotification(oldEmail, user, c); err != nil {
			log.WithFields(log.Fields{
				"username": claims.Username,
				"err":      err,
			}).Error("Failed to notify old address about email change")
		}
	}

	log.WithFields(log.Fields{
		"username":  claims.Username,
		"old_email": oldEmail,
		"new_email": claims.Email,
		"ip":        RemoteIP(c),
	}).Info("AUDIT email address changed successfully")

	return c.Render("email-change-success.html", fiber.Map{})
}
