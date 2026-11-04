package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa"
	"github.com/spf13/viper"
)

var (
	ErrDomainNotAllowed = errors.New("Email domain not allowed")
	ErrInvalidUsername  = errors.New("Username is invalid. May only include letters, numbers, _, -, .")

	usernameRegx = regexp.MustCompile("^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,31}$")
	rxUsername   = regexp.MustCompile("[^a-zA-Z0-9_.-]")
	// dotted hostname, non-ASCII labels allowed
	rxEmailDomain = regexp.MustCompile(`^(?:[\p{L}\p{N}](?:[\p{L}\p{N}._~-]*[\p{L}\p{N}])?\.)+[\p{L}](?:[\p{L}\p{N}_~-]*[\p{L}])?$`)
)

// isEmail accepts a bare addr-spec (no display name, no quoted local part)
// with a dotted domain
func isEmail(s string) bool {
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return false
	}
	at := strings.LastIndex(s, "@")
	return rxEmailDomain.MatchString(s[at+1:])
}

func defaultUsernameGenerator(username string) string {
	return rxUsername.ReplaceAllString(username, "")
}

func flastUsernameGenerator(username string) string {
	dot := strings.Index(username, ".")
	first, last := username[:dot], username[dot+1:]
	username = last
	if first != "" {
		username = string(first[0]) + last
	}
	return rxUsername.ReplaceAllString(username, "")
}

func generateUsernameFromEmail(user *ipa.User, allowedDomains map[string]string) error {
	at := strings.LastIndex(user.Email, "@")
	username, domain := user.Email[:at], strings.ToLower(user.Email[at+1:])

	if len(allowedDomains) == 0 {
		user.Username = defaultUsernameGenerator(username)
	} else {
		if _, ok := allowedDomains[domain]; !ok {
			return fmt.Errorf("%w: %s", ErrDomainNotAllowed, domain)
		}

		switch allowedDomains[domain] {
		case "flast":
			user.Username = flastUsernameGenerator(username)
		default:
			user.Username = defaultUsernameGenerator(username)
		}
	}

	if user.Username == "" {
		return fmt.Errorf("%w: %s", ErrInvalidUsername, user.Email)
	}

	return nil
}

func validateEmail(user *ipa.User, allowedDomains map[string]string) error {
	if !isEmail(user.Email) {
		return errors.New("Please provide a valid email address")
	}

	if len(allowedDomains) > 0 {
		at := strings.LastIndex(user.Email, "@")
		_, domain := user.Email[:at], strings.ToLower(user.Email[at+1:])

		if _, ok := allowedDomains[domain]; !ok {
			return fmt.Errorf("%w: %s", ErrDomainNotAllowed, domain)
		}
	}

	return nil
}

func validateUsername(user *ipa.User) error {
	allowedDomains := viper.GetStringMapString("accounts.allowed_domains")

	if err := validateEmail(user, allowedDomains); err != nil {
		return err
	}

	if viper.GetBool("accounts.username_from_email") {
		if err := generateUsernameFromEmail(user, allowedDomains); err != nil {
			return err
		}
	}

	if !usernameRegx.MatchString(user.Username) {
		return fmt.Errorf("%w: %s", ErrInvalidUsername, user.Username)
	}

	if isDigits(user.Username) {
		return errors.New("Username must include at least one letter")
	}

	if isBlocked(user.Username) {
		return errors.New("Username not allowed. Please try different username or contact the administrator")
	}

	user.Username = strings.ToLower(user.Username)

	return nil
}

// UsernameForgot emails the username(s) tied to an address. The response is
// identical whether or not the address matches an account — no enumeration.
func (r *Router) UsernameForgot(c fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		return c.Render("username-forgot.html", fiber.Map{
			"captchaID": newCaptchaID(),
		})
	}

	if err := r.verifyCaptcha(c.FormValue("captcha_id"), c.FormValue("captcha_sol")); err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+newCaptchaID()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	email := strings.TrimSpace(strings.ToLower(c.FormValue("email")))
	if email == "" || !isEmail(email) {
		return c.Render("username-forgot-success.html", fiber.Map{})
	}

	users, err := r.adminClient.UserFind(ipa.Options{"mail": email})
	if err != nil {
		slog.Error("Forgot username failed to search FreeIPA",
			"email", email,
			"err", err,
		)
		return c.Render("username-forgot-success.html", fiber.Map{})
	}

	usernames := []string{}
	for _, u := range users {
		// user_find matches substrings — require the exact address, and
		// skip accounts that can't log in anyway
		if strings.EqualFold(u.Email, email) && !u.Locked && !isBlocked(u.Username) {
			usernames = append(usernames, u.Username)
		}
	}

	if len(usernames) > 0 {
		if err := r.emailer.SendUsernameReminderEmail(email, usernames, c); err != nil {
			slog.Error("Failed to send username reminder email",
				"email", email,
				"err", err,
			)
		} else {
			slog.Info("AUDIT Username reminder email sent",
				"email", email,
			)
		}
	} else {
		slog.Info("Forgot username request for unknown email",
			"email", email,
		)
	}

	return c.Render("username-forgot-success.html", fiber.Map{})
}
