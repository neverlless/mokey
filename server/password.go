package server

import (
	"errors"
	"fmt"
	"time"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

// Simple password checker to validate passwords before creating an account
func checkPassword(pass string) error {
	minLength := viper.GetInt("accounts.min_passwd_len")
	minClasses := viper.GetInt("accounts.min_passwd_classes")

	l := len([]rune(pass))
	if l < minLength {
		return fmt.Errorf(T("password.min_length"), minLength)
	}

	// Category counting mirrors FreeIPA's util/ipa_pwd.c: five classes
	// (digits, uppercase, lowercase, ASCII specials, other non-ASCII), and
	// a one-class penalty only for characters repeated three or more times
	// in a row (max_repeated counts adjacent equal PAIRS; the penalty
	// applies when it exceeds one). See ubccr/mokey#170.
	var hasDigit, hasUpper, hasLower, hasSpecial, has8bit bool
	runes := []rune(pass)
	numRepeated, maxRepeated := 0, 0
	for i, r := range runes {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r < 128:
			hasSpecial = true
		default:
			has8bit = true
		}

		if i > 0 && runes[i-1] == r {
			numRepeated++
			if numRepeated > maxRepeated {
				maxRepeated = numRepeated
			}
		} else {
			numRepeated = 0
		}
	}

	numCategories := 0
	for _, has := range []bool{hasDigit, hasUpper, hasLower, hasSpecial, has8bit} {
		if has {
			numCategories++
		}
	}
	if maxRepeated > 1 {
		numCategories--
	}

	if numCategories < minClasses {
		return errors.New(T("password.policy_not_met"))
	}

	return nil
}

func validatePassword(password, passwordConfirm string) error {
	if password == "" {
		return errors.New(T("password.enter_new"))
	}

	if passwordConfirm == "" {
		return errors.New(T("password.confirm_new"))
	}

	if password != passwordConfirm {
		return errors.New("Password do not match. Please confirm your password.")
	}

	if err := checkPassword(password); err != nil {
		return err
	}

	return nil
}

func validatePasswordChange(passwordCurrent, password, passwordConfirm string) error {
	if passwordCurrent == "" {
		return errors.New(T("password.enter_current"))
	}

	if passwordCurrent == passwordConfirm {
		return errors.New(T("password.same_as_new"))
	}

	return validatePassword(password, passwordConfirm)
}

func (r *Router) PasswordChange(c *fiber.Ctx) error {
	user := r.user(c)
	client := r.userClient(c)

	vars := fiber.Map{
		"user": user,
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("password.html", vars)
	}

	password := c.FormValue("password")
	newpass := c.FormValue("newpassword")
	newpass2 := c.FormValue("newpassword2")
	otp := c.FormValue("otpcode")

	if user.OTPOnly() && otp == "" {
		vars["message"] = T("otptoken.enter_6_digit_code_help")
		return c.Render("password.html", vars)
	}

	if err := validatePasswordChange(password, newpass, newpass2); err != nil {
		vars["message"] = err.Error()
		return c.Render("password.html", vars)
	}

	err := client.ChangePassword(user.Username, password, newpass, otp)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); ok {
			log.WithFields(log.Fields{
				"username": user.Username,
				"message":  ierr.Message,
				"code":     ierr.Code,
			}).Error("Failed to change password")
			vars["message"] = ierr.Message
		} else {
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err.Error(),
			}).Error("Failed to change password")
			vars["message"] = T("account.fatal_system_error")
		}
	} else {
		// Kill other active sessions; keep this one by refreshing its
		// login time past the invalidation marker
		r.invalidateUserSessions(user.Username)
		if sess, serr := r.session(c); serr == nil {
			sess.Set(SessionKeyLoginTime, time.Now().Unix())
			if serr := r.sessionSave(c, sess); serr != nil {
				log.WithFields(log.Fields{
					"username": user.Username,
					"err":      serr,
				}).Error("Failed to refresh session after password change")
			}
		}

		err = r.emailer.SendPasswordChangedEmail(user, c)
		if err != nil {
			log.WithFields(log.Fields{
				"err":      err,
				"username": user.Username,
				"email":    user.Email,
			}).Error("Failed to send password changed email")
		}

		vars["success"] = true
	}

	return c.Render("password.html", vars)
}

func (r *Router) PasswordForgot(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"captchaID": captcha.New(),
		}

		return c.Render("password-forgot.html", vars)
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
		}).Warn("AUDIT Forgot password attempt for blocked username")
		return c.Render("password-forgot-success.html", fiber.Map{})
	}

	user, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Warn("AUDIT Forgot password attempt for unknown username")
		return c.Render("password-forgot-success.html", fiber.Map{})
	}

	if user.Locked {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT Forgot password attempt for disabled/locked user")
		return c.Render("password-forgot-success.html", fiber.Map{})
	}

	// Send user a reset password email
	err = r.emailer.SendPasswordResetEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to send reset password email")
	} else {
		log.WithFields(log.Fields{
			"username": user.Username,
			"email":    user.Email,
		}).Info("Password reset email sent successfully")
		r.metrics.totalPasswordResetsSent.Inc()
	}

	return c.Render("password-forgot-success.html", fiber.Map{})
}

func (r *Router) PasswordReset(c *fiber.Ctx) error {
	token := c.Params("token")

	claims, err := ParseToken(token, TokenPasswordReset, r.storage)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	user, err := r.adminClient.UserShow(claims.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": claims.Username,
			"email":    claims.Email,
		}).Warn("Attempt to reset password for non-existent username")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if user.Locked {
		log.WithFields(log.Fields{
			"username": claims.Username,
			"email":    claims.Email,
		}).Warn("AUDIT Attempt to reset password for disabled/locked user")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"claims": claims,
			"user":   user,
		}

		return c.Render("password-reset.html", vars)
	}

	password := c.FormValue("password")
	passwordConfirm := c.FormValue("password2")
	otp := c.FormValue("otpcode")

	if user.OTPOnly() && otp == "" {
		return c.Status(fiber.StatusBadRequest).SendString(T("otptoken.enter_6_digit_code_help"))
	}

	if err := validatePassword(password, passwordConfirm); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	rand, err := r.adminClient.ResetPassword(user.Username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.system_error"))
	}

	err = r.adminClient.SetPassword(user.Username, rand, password, otp)
	if err != nil {
		switch {
		case errors.Is(err, ipa.ErrPasswordPolicy):
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err,
			}).Error("Password does not conform to policy")
			return c.Status(fiber.StatusBadRequest).SendString(T("account.weak_password"))
		case errors.Is(err, ipa.ErrInvalidPassword):
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err,
			}).Error("invalid password from FreeIPA")
			return c.Status(fiber.StatusBadRequest).SendString(T("otptoken.invalid_otp"))
		default:
			log.WithFields(log.Fields{
				"username": user.Username,
				"error":    err,
			}).Error("failed to set user password in FreeIPA")
			return c.Status(fiber.StatusInternalServerError).SendString(T("account.system_error"))
		}
	}

	r.storage.Set(TokenPasswordReset+TokenUsedPrefix+token, []byte("true"), time.Until(claims.Timestamp.Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second)))
	r.invalidateUserSessions(user.Username)

	err = r.emailer.SendPasswordChangedEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to send password changed email")
	}

	log.WithFields(log.Fields{
		"username": user.Username,
	}).Info("AUDIT User password changed successfully")
	r.metrics.totalPasswordResets.Inc()

	return c.Render("password-reset-success.html", fiber.Map{})
}

func (r *Router) PasswordExpired(c *fiber.Ctx) error {
	sess, err := r.session(c)
	if err != nil {
		log.Warn("Failed to get user session. Logging out")
		return r.redirectLogin(c)
	}

	username := sess.Get(SessionKeyUsername)
	authenticated := sess.Get(SessionKeyAuthenticated)
	if username == nil || authenticated == nil {
		return r.redirectLogin(c)
	}

	if isAuthed, ok := authenticated.(bool); !ok || isAuthed {
		return r.redirectLogin(c)
	}

	if _, ok := username.(string); !ok {
		log.Error("Invalid user in session")
		return r.redirectLogin(c)
	}

	user, err := r.adminClient.UserShow(username.(string))
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Warn("Password expired attempt for unknown username")
		return r.redirectLogin(c)
	}

	password := c.FormValue("password")
	newpass := c.FormValue("newpassword")
	newpass2 := c.FormValue("newpassword2")
	otp := c.FormValue("otp")

	if user.OTPOnly() && otp == "" {
		return c.Status(fiber.StatusBadRequest).SendString(T("otptoken.enter_6_digit_code_help"))
	}

	if err := validatePasswordChange(password, newpass, newpass2); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	err = r.adminClient.SetPassword(user.Username, password, newpass, otp)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to change expired password for user")

		return c.Status(fiber.StatusInternalServerError).SendString("")
	}

	r.invalidateUserSessions(user.Username)

	err = r.emailer.SendPasswordChangedEmail(user, c)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to send password changed email")
	}

	// A TOTP code is single-use and was just consumed by SetPassword.
	// Re-using it for the automatic login below would be rejected by
	// FreeIPA as a replay, showing the user an error even though the
	// password was changed (ubccr/mokey#127). Skip auto-login for OTP
	// users and ask them to log in with a fresh code instead.
	if user.OTPOnly() {
		log.WithFields(log.Fields{
			"username": user.Username,
		}).Info("AUDIT User changed expired password successfully")
		r.metrics.totalPasswordResets.Inc()
		c.Set("HX-Redirect", "/auth/login")
		return c.Status(fiber.StatusNoContent).SendString("")
	}

	client := newIPAClient()
	err = client.RemoteLogin(user.Username, newpass+otp)
	if err != nil {
		log.WithFields(log.Fields{
			"username":         user.Username,
			"ipa_client_error": err,
		}).Error("Failed to login after expired password change")
		return c.Status(fiber.StatusUnauthorized).SendString(T("login.failed"))
	}

	_, err = client.Ping()
	if err != nil {
		log.WithFields(log.Fields{
			"username":         user.Username,
			"ipa_client_error": err,
		}).Error("Failed to ping FreeIPA after expired password change")
		return c.Status(fiber.StatusUnauthorized).SendString(T("account.invalid_credentials"))
	}

	sess.Set(SessionKeyAuthenticated, true)
	sess.Set(SessionKeyUsername, user.Username)
	sess.Set(SessionKeySID, client.SessionID())
	sess.Set(SessionKeyLoginTime, time.Now().Unix())

	if err := r.sessionSave(c, sess); err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"username": user.Username,
	}).Info("AUDIT User logged in and changed expired password successfully")
	r.metrics.totalPasswordResets.Inc()

	c.Set("HX-Redirect", "/")
	return c.Status(fiber.StatusNoContent).SendString("")
}
