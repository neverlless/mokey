package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	ipa "github.com/neverlless/goipa"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Simple password checker to validate passwords before creating an account
// checkPassword enforces the stricter of mokey's configured minimums and the
// password policy FreeIPA actually applies. The config alone silently drifts
// from the directory (ubccr/mokey#16), and stageuser_add applies no policy at
// all, so a staged signup would otherwise accept a password FreeIPA rejects.
// A nil policy means the lookup failed; fall back to the config.
func checkPassword(pass, username string, policy *PwPolicy) error {
	minLength := viper.GetInt("accounts.min_passwd_len")
	minClasses := viper.GetInt("accounts.min_passwd_classes")

	pwquality := policy != nil && policy.pwquality()
	if policy != nil {
		// libpwquality replaces FreeIPA's plain length check, see checkPwquality
		if !pwquality && policy.MinLength > minLength {
			minLength = policy.MinLength
		}
		if policy.MinClasses > minClasses {
			minClasses = policy.MinClasses
		}
	}

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

	if pwquality {
		return checkPwquality(pass, username, policy)
	}

	return nil
}

// checkPwquality runs libpwquality's checks the way FreeIPA 4.13 configures
// them, in libpwquality's order. Like libpwquality it works on bytes:
// counting runes would reject non-ASCII passwords FreeIPA accepts. The
// dictionary check (cracklib) is left to FreeIPA.
func checkPwquality(pass, username string, p *PwPolicy) error {
	b := []byte(pass)
	mono := slices.Clone(b)
	for i, c := range mono {
		if c >= 'A' && c <= 'Z' {
			mono[i] = c + 'a' - 'A'
		}
	}

	var digits, uppers, lowers, others int
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'A' && c <= 'Z':
			uppers++
		case c >= 'a' && c <= 'z':
			lowers++
		default:
			others++
		}
	}

	// shortcut: length counts runes while libpwquality counts bytes, so a
	// non-ASCII password near the minimum may be refused here although
	// FreeIPA would take it; count bytes if that ever bites
	size := len([]rune(pass))
	for _, class := range []struct {
		count, credit int
		tooFew        string
	}{
		{digits, p.DigitCredit, "password.too_few_digits"},
		{uppers, p.UpperCredit, "password.too_few_upper"},
		{lowers, p.LowerCredit, "password.too_few_lower"},
		{others, p.OtherCredit, "password.too_few_special"},
	} {
		if class.count < -class.credit {
			return errors.New(T(class.tooFew))
		}
		if class.credit > 0 {
			size += min(class.count, class.credit)
		}
	}
	// libpwquality's floor; FreeIPA refuses a lower minlength for such policies anyway
	if minLength := max(p.MinLength, 6); size < minLength {
		return fmt.Errorf(T("password.min_length"), minLength)
	}

	rev := slices.Clone(mono)
	slices.Reverse(rev)
	if bytes.Equal(mono, rev) {
		return errors.New(T("password.palindrome"))
	}

	if p.MaxRepeat > 0 && longestRun(b, 0) > p.MaxRepeat {
		return errors.New(T("password.too_many_repeats"))
	}
	if p.MaxSequence > 0 && max(longestRun(b, 1), longestRun(b, -1)) > p.MaxSequence {
		return errors.New(T("password.sequence"))
	}

	if user := strings.ToLower(username); p.UserCheck && len(user) >= 4 {
		resu := []byte(user)
		slices.Reverse(resu)
		if bytes.Contains(mono, []byte(user)) || bytes.Contains(mono, resu) {
			return errors.New(T("password.contains_username"))
		}
	}

	return nil
}

// longestRun is the length of the longest stretch of b in which each byte
// is the previous one plus step. libpwquality compares signed chars.
func longestRun(b []byte, step int) int {
	longest, run := min(len(b), 1), 1
	for i := 1; i < len(b); i++ {
		if int(int8(b[i]))-int(int8(b[i-1])) == step { // #nosec G115 -- wraps on purpose, as C char
			run++
		} else {
			run = 1
		}
		longest = max(longest, run)
	}
	return longest
}

func validatePassword(password, passwordConfirm, username string, policy *PwPolicy) error {
	if password == "" {
		return errors.New(T("password.enter_new"))
	}

	if passwordConfirm == "" {
		return errors.New(T("password.confirm_new"))
	}

	if password != passwordConfirm {
		return errors.New("Password do not match. Please confirm your password.")
	}

	if err := checkPassword(password, username, policy); err != nil {
		return err
	}

	if viper.GetBool("accounts.check_breached_passwords") {
		breached, err := passwordBreached(password)
		if err != nil {
			// fail open: an unreachable API must not lock users out of password changes
			log.WithFields(log.Fields{
				"username": username,
				"err":      err,
			}).Warn("Breached-password check failed, accepting password")
		} else if breached {
			return errors.New(T("password.breached"))
		}
	}

	return nil
}

func validatePasswordChange(passwordCurrent, password, passwordConfirm, username string, policy *PwPolicy) error {
	if passwordCurrent == "" {
		return errors.New(T("password.enter_current"))
	}

	if passwordCurrent == passwordConfirm {
		return errors.New(T("password.same_as_new"))
	}

	return validatePassword(password, passwordConfirm, username, policy)
}

// usesFreeIPAPassword reports whether ipauserauthtype values let the user
// sign in with their FreeIPA password: otp is that password plus a token,
// hardened the same password over FAST. No values means password.
func usesFreeIPAPassword(types []string) bool {
	if len(types) == 0 {
		return true
	}
	for _, t := range types {
		switch t {
		case "password", "otp", "hardened":
			return true
		}
	}
	return false
}

// passwordElsewhere explains why user has no FreeIPA password to change or
// reset, or returns "" when they have one. The user's ipauserauthtype falls
// back to the server-wide default, which also wins outright when it
// contains "disabled" (per-user types switched off).
func (r *Router) passwordElsewhere(user *ipa.User) string {
	types := user.AuthTypes
	if global := r.defaultAuthTypes(); len(types) == 0 || slices.Contains(global, "disabled") {
		types = slices.DeleteFunc(global, func(t string) bool { return t == "disabled" })
	}

	switch {
	case usesFreeIPAPassword(types):
		return ""
	case slices.Contains(types, "idp"):
		return T("password.managed_by_idp")
	case slices.Contains(types, "radius"):
		return T("password.managed_by_radius")
	}
	return T("password.not_used")
}

// defaultAuthTypes is the server-wide ipauserauthtype; nil when FreeIPA
// does not answer, so mokey then goes by the user's own types
func (r *Router) defaultAuthTypes() []string {
	// goipa has no typed config_show yet (neverlless/goipa#23)
	res, err := r.adminClient.RPC("config_show", nil, nil)
	if err != nil || res.Result == nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Warn("Failed to fetch the default user authentication types")
		return nil
	}

	var config struct {
		AuthTypes []string `json:"ipauserauthtype"`
	}
	if err := json.Unmarshal(res.Result.Data, &config); err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Warn("Failed to decode the default user authentication types")
		return nil
	}
	return config.AuthTypes
}

// adTrustUsername reports whether username is qualified with a domain other
// than FreeIPA's own (user@ad.example.com, AD\user): a trusted Active
// Directory user, whose password FreeIPA cannot change. It goes by the
// input alone, so answering differently for it reveals no account.
func (r *Router) adTrustUsername(username string) bool {
	if strings.Contains(username, `\`) {
		return true
	}
	at := strings.LastIndex(username, "@")
	// shortcut: assumes the IPA domain is the realm in lowercase; compare
	// against the IPA domain too if a site's differ
	return at >= 0 && !strings.EqualFold(username[at+1:], r.adminClient.Realm())
}

// pwPolicyVars puts the user's password policy on the page, if FreeIPA
// returns it
func (r *Router) pwPolicyVars(username string, vars fiber.Map) {
	if policy, err := pwPolicyShow(r.adminClient, username); err == nil {
		vars["pwpolicy"] = policy
	} else {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Warn("Failed to fetch password policy for display")
	}
}

func (r *Router) PasswordChange(c *fiber.Ctx) error {
	user := r.user(c)
	client := r.userClient(c)

	vars := fiber.Map{
		"user": user,
	}

	if msg := r.passwordElsewhere(user); msg != "" {
		if c.Method() != fiber.MethodGet {
			return c.Status(fiber.StatusForbidden).SendString(msg)
		}
		vars["password_elsewhere"] = msg
		return c.Render("password.html", vars)
	}

	// every render of this page shows the policy, including the one that
	// reports a rejected password — that is when the user needs it most
	r.pwPolicyVars(user.Username, vars)

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

	policy, _ := vars["pwpolicy"].(*PwPolicy)
	if err := validatePasswordChange(password, newpass, newpass2, user.Username, policy); err != nil {
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
			"captchaID": newCaptchaID(),
		}

		return c.Render("password-forgot.html", vars)
	}

	username := c.FormValue("username")
	if r.adTrustUsername(username) {
		return c.Status(fiber.StatusBadRequest).SendString(T("password.managed_by_ad"))
	}

	err := r.verifyCaptcha(c.FormValue("captcha_id"), c.FormValue("captcha_sol"))
	if err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+captcha.New()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

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

	// no reset link: a FreeIPA password would not let them sign in
	if reason := r.passwordElsewhere(user); reason != "" {
		log.WithFields(log.Fields{
			"username": username,
		}).Warn("AUDIT Forgot password attempt for user without a FreeIPA password")
		if err := r.emailer.SendPasswordElsewhereEmail(user, reason, c); err != nil {
			log.WithFields(log.Fields{
				"err":      err,
				"username": user.Username,
				"email":    user.Email,
			}).Error("Failed to send password managed elsewhere email")
		}
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

	// the same page either way: showing a delivery error only for accounts
	// that exist would turn this form into an enumeration oracle. The
	// operator's signal is the log line above plus a flat
	// mokey_password_reset_sent_total (#31)
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

	if r.passwordElsewhere(user) != "" {
		log.WithFields(log.Fields{
			"username": claims.Username,
		}).Warn("AUDIT Attempt to reset password for user without a FreeIPA password")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	policy, err := pwPolicyShow(r.adminClient, user.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": user.Username,
			"err":      err,
		}).Warn("Failed to fetch password policy")
		policy = nil
	}

	if c.Method() == fiber.MethodGet {
		vars := fiber.Map{
			"claims": claims,
			"user":   user,
		}
		if policy != nil {
			vars["pwpolicy"] = policy
		}

		return c.Render("password-reset.html", vars)
	}

	password := c.FormValue("password")
	passwordConfirm := c.FormValue("password2")
	otp := c.FormValue("otpcode")

	if user.OTPOnly() && otp == "" {
		return c.Status(fiber.StatusBadRequest).SendString(T("otptoken.enter_6_digit_code_help"))
	}

	if err := validatePassword(password, passwordConfirm, user.Username, policy); err != nil {
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

	MarkTokenUsed(token, TokenPasswordReset, claims, r.storage)
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

	if r.passwordElsewhere(user) != "" {
		return r.redirectLogin(c)
	}

	password := c.FormValue("password")
	newpass := c.FormValue("newpassword")
	newpass2 := c.FormValue("newpassword2")
	otp := c.FormValue("otp")

	if user.OTPOnly() && otp == "" {
		return c.Status(fiber.StatusBadRequest).SendString(T("otptoken.enter_6_digit_code_help"))
	}

	policy, perr := pwPolicyShow(r.adminClient, user.Username)
	if perr != nil {
		policy = nil
	}

	if err := validatePasswordChange(password, newpass, newpass2, user.Username, policy); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	err = r.adminClient.SetPassword(user.Username, password, newpass, otp)
	if err != nil {
		log.WithFields(log.Fields{
			"err":      err,
			"username": user.Username,
			"email":    user.Email,
		}).Error("Failed to change expired password for user")

		// FreeIPA says why it refused; answering with an empty 500 turned
		// that into a generic error for the user (ubccr/mokey#18)
		switch {
		case errors.Is(err, ipa.ErrPasswordPolicy):
			return c.Status(fiber.StatusBadRequest).SendString(T("password.rejected_by_policy"))
		case errors.Is(err, ipa.ErrInvalidPassword):
			return c.Status(fiber.StatusBadRequest).SendString(T("password.invalid_current"))
		}
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

	client, err := newIPAClient()
	if err != nil {
		return err
	}
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

	// Rotate the session id on privilege elevation, mirroring Authenticate
	if err := sess.Regenerate(); err != nil {
		return err
	}

	sess.Set(SessionKeyAuthenticated, true)
	sess.Set(SessionKeyUsername, user.Username)
	sess.Set(SessionKeySID, client.SessionID())
	sess.Set(SessionKeyLoginTime, time.Now().Unix())

	// capture before Save — fiber releases the session object on Save
	sid := sess.ID()

	if err := r.sessionSave(c, sess); err != nil {
		return err
	}

	r.recordUserSession(c, user.Username, sid)
	r.notifyNewLogin(c, user.Username)

	log.WithFields(log.Fields{
		"username": user.Username,
	}).Info("AUDIT User logged in and changed expired password successfully")
	r.metrics.totalPasswordResets.Inc()

	c.Set("HX-Redirect", "/")
	return c.Status(fiber.StatusNoContent).SendString("")
}
