package server

import (
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
)

// LogLevel is shared by every handler NewLogHandler builds, so the router
// can rebuild the default logger without losing the --loglevel setting.
var LogLevel = new(slog.LevelVar)

const redacted = "[REDACTED]"

var secretLogKeys = map[string]bool{
	"password":         true,
	"password2":        true,
	"newpassword":      true,
	"new_password":     true,
	"current_password": true,
	"otp":              true,
	"otpcode":          true,
	"otp_code":         true,
	"totp":             true,
	"passcode":         true,
	"token":            true,
	"secret":           true,
	"client_secret":    true,
	"token_secret":     true,
	"csrf_secret":      true,
	"smtp_password":    true,
	"private_key":      true,
	"authorization":    true,
	"cookie":           true,
}

// userinfo of any scheme://user:pass@ URL, parseable or not
var urlPasswordRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:"]*:)[^\s/@"]*@`)

func NewLogHandler(w io.Writer) slog.Handler {
	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: LogLevel, ReplaceAttr: redactAttr})
}

// redactAttr blanks values logged under secret keys and URL passwords
// anywhere in string or error values, including the message.
func redactAttr(_ []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	if secretLogKeys[key] || strings.HasSuffix(key, "_password") || strings.HasSuffix(key, "_secret") {
		return slog.String(a.Key, redacted)
	}

	var s string
	switch a.Value.Kind() {
	case slog.KindString:
		s = a.Value.String()
	case slog.KindAny:
		err, ok := a.Value.Any().(error)
		if !ok {
			return a
		}
		s = err.Error()
	default:
		return a
	}
	if r := redactURLs(s); r != s {
		return slog.String(a.Key, r)
	}
	return a
}

func redactURLs(s string) string {
	return urlPasswordRe.ReplaceAllString(s, "${1}"+redacted+"@")
}

// redactURL hides the password of a URL for logging; unparseable URLs still
// get their userinfo password masked.
func redactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Redacted()
	}
	return redactURLs(raw)
}
