package server

import (
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/neverlless/goipa"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/viper"
)

func getHashAlgorithm() otp.Algorithm {
	algo := viper.GetString("accounts.otp_hash_algorithm")
	switch algo {
	case "sha256":
		return otp.AlgorithmSHA256
	case "sha512":
		return otp.AlgorithmSHA512
	default:
		return otp.AlgorithmSHA1
	}
}

// otpReadonly reports whether the user's OTP tokens are admin-managed:
// membership in any accounts.otp_readonly_groups group makes the OTP page
// view-only (e.g. orgs issuing hardware tokens centrally)
func otpReadonly(user *ipa.User) bool {
	for _, group := range viper.GetStringSlice("accounts.otp_readonly_groups") {
		if user.HasGroup(group) {
			return true
		}
	}
	return false
}

// RequireOTPSelfService blocks OTP mutations for read-only users. The
// buttons are hidden in the UI, but enforcement lives here.
func (r *Router) RequireOTPSelfService(c *fiber.Ctx) error {
	if otpReadonly(r.user(c)) {
		return c.Status(fiber.StatusForbidden).SendString(TC(c, "otptoken.readonly_notice"))
	}
	return c.Next()
}

func (r *Router) tokenList(c *fiber.Ctx, vars fiber.Map) error {
	client := r.userClient(c)
	user := r.user(c)

	tokens, err := client.FetchOTPTokens(user.Username)
	if err != nil {
		return err
	}

	vars["otptokens"] = tokens
	vars["user"] = user
	vars["otp_readonly"] = otpReadonly(user)
	return c.Render("otptoken-list.html", vars)
}

func (r *Router) OTPTokenList(c *fiber.Ctx) error {
	return r.tokenList(c, fiber.Map{})
}

func (r *Router) OTPTokenModal(c *fiber.Ctx) error {
	vars := fiber.Map{}
	return c.Render("otptoken-new.html", vars)
}

func (r *Router) OTPTokenRemove(c *fiber.Ctx) error {
	uuid := c.FormValue("uuid")
	client := r.userClient(c)
	user := r.user(c)
	vars := fiber.Map{}

	err := client.RemoveOTPToken(uuid)
	if err != nil {
		slog.Error("Failed to remove OTP token",
			"uuid", uuid,
			"username", user.Username,
			"err", err,
		)

		if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4203 {
			vars["message"] = "You can't remove your last active token while Two-Factor auth is enabled"
		} else {
			vars["message"] = "Failed to remove token"
		}
	} else {
		err = r.emailer.SendOTPTokenUpdatedEmail(false, user, c)
		if err != nil {
			slog.Error("Failed to send otp token removed email",
				"err", err,
				"username", user.Username,
			)
		}
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenEnable(c *fiber.Ctx) error {
	uuid := c.FormValue("uuid")
	client := r.userClient(c)
	username := r.username(c)
	vars := fiber.Map{}

	err := client.EnableOTPToken(uuid)
	if err != nil {
		slog.Error("Failed to enable OTP token",
			"uuid", uuid,
			"username", username,
			"err", err,
		)
		vars["message"] = "Failed to enable token"
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenDisable(c *fiber.Ctx) error {
	uuid := c.FormValue("uuid")
	client := r.userClient(c)
	username := r.username(c)
	vars := fiber.Map{}

	err := client.DisableOTPToken(uuid)
	if err != nil {
		slog.Error("Failed to enable OTP token",
			"uuid", uuid,
			"username", username,
			"err", err,
		)

		if ierr, ok := err.(*ipa.IpaError); ok && ierr.Code == 4203 {
			vars["message"] = "You can't disable your last active token while Two-Factor auth is enabled"
		} else {
			vars["message"] = "Failed to disable token"
		}
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenVerify(c *fiber.Ctx) error {
	otpcode := c.FormValue("otpcode")
	uri := c.FormValue("uri")
	uuid := c.FormValue("uuid")
	action := c.FormValue("action")
	client := r.userClient(c)
	user := r.user(c)
	vars := fiber.Map{}

	// Backing out of the QR dialog is a deliberate choice, not a failure:
	// drop the unverified token and return to the list without an alarm
	// (ubccr/mokey#20)
	if action == "cancel" {
		if err := client.RemoveOTPToken(uuid); err != nil {
			slog.Error("Failed to remove unverified OTP token",
				"uuid", uuid,
				"username", user.Username,
				"err", err,
			)
		}
		return r.tokenList(c, vars)
	}

	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		// the url.Error would quote the URI, and with it the TOTP secret
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		slog.Error("Failed to parse OTP token URI",
			"uuid", uuid,
			"username", user.Username,
			"err", err,
		)
		if err := client.RemoveOTPToken(uuid); err != nil {
			slog.Error("Failed to remove unverified OTP token",
				"uuid", uuid,
				"username", user.Username,
				"err", err,
			)
		}
		vars["message"] = TC(c, "otptoken.failed_to_verify_token")
		return r.tokenList(c, vars)
	}

	valid, _ := totp.ValidateCustom(
		otpcode,
		key.Secret(),
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: getHashAlgorithm(),
		},
	)
	if !valid {
		slog.Error("Failed to verify OTP token",
			"uuid", uuid,
			"username", user.Username,
		)
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, "otptoken.invalid_6_digit_code"))
	}

	autoMFA := false
	if viper.GetBool("accounts.require_mfa") {
		tokens, _ := client.FetchOTPTokens(user.Username)
		// Enable Two-Factor auth automatically if user only has single token
		if !user.OTPOnly() && len(tokens) == 1 {
			otpOnly := []string{"otp"}
			err = r.adminClient.SetAuthTypes(user.Username, otpOnly)
			if err != nil {
				slog.Error("Failed to automatically enable Two-Factor auth",
					"username", user.Username,
					"err", err,
				)
			} else {
				autoMFA = true
				user.AuthTypes = otpOnly
				c.Locals(ContextKeyUser, user)

				err = r.emailer.SendMFAChangedEmail(true, user, c)
				if err != nil {
					slog.Error("Failed to send mfa automatically enabled email",
						"err", err,
						"username", user.Username,
					)
				}
			}
		}
	}

	if !autoMFA {
		err = r.emailer.SendOTPTokenUpdatedEmail(true, user, c)
		if err != nil {
			slog.Error("Failed to send otp token added email",
				"err", err,
				"username", user.Username,
			)
		}
	}

	return r.tokenList(c, vars)
}

func (r *Router) OTPTokenAdd(c *fiber.Ctx) error {
	client := r.userClient(c)

	desc := c.FormValue("desc")

	// NotBefore must be UTC: goipa formats it as LDAP generalized time
	// with a literal Z, so a local timestamp lands in the future and the
	// token rejects codes until the offset elapses (ubccr#159)
	token, err := client.AddOTPToken(
		&ipa.OTPToken{
			Type:        ipa.TokenTypeTOTP,
			Algorithm:   strings.ToLower(getHashAlgorithm().String()),
			Description: desc,
			NotBefore:   time.Now().UTC(),
		})

	if err != nil {
		return err
	}

	otpdata, err := QRCode(token, client.Realm())
	if err != nil {
		return err
	}

	vars := fiber.Map{
		"otpdata":  otpdata,
		"otptoken": token,
	}
	return c.Render("otptoken-scan.html", vars)
}
