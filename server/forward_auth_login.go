package server

import (
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
)

const (
	faContinuePath      = "/forward-auth/continue"
	SessionKeyLoginNext = "login_next"
)

// safeNextPath keeps next only when it is a same-origin path, else "/"
func safeNextPath(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) ||
		strings.IndexFunc(next, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "/"
	}
	return next
}

// setLoginNext remembers where to send the user after sign-in
func (r *Router) setLoginNext(c fiber.Ctx, next string) {
	sess, err := r.session(c)
	if err != nil {
		return
	}
	sess.Set(SessionKeyLoginNext, safeNextPath(next))
	_ = r.sessionSave(c, sess) // logged there; the user then lands on "/"
}

// takeLoginNext returns the remembered page, or "/", and forgets it. It
// works on the caller's session: after Regenerate a second store lookup in
// the same request starts an empty session.
func takeLoginNext(sess *session.Session) string {
	next, _ := sess.Get(SessionKeyLoginNext).(string)
	sess.Delete(SessionKeyLoginNext)
	return safeNextPath(next)
}
