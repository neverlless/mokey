package server

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
	"github.com/valyala/fasthttp"
)

const (
	faSessionCookie = "__Host-mokey_fa"
	faNonceCookie   = "__Host-mokey_fa_nonce"
	faSignedOutPath = "/forward-auth/signedout"
)

// faCookie sets or, with an empty value, deletes a __Host- cookie; browsers
// ignore a deletion that lacks the prefix's attributes
func faCookie(c fiber.Ctx, name, value string, maxAge time.Duration) {
	ck := &fiber.Cookie{Name: name, Value: value, Path: "/", Secure: true, HTTPOnly: true, SameSite: fiber.CookieSameSiteLaxMode}
	if value == "" {
		ck.Expires = fasthttp.CookieExpireDelete
	} else {
		ck.MaxAge = int(maxAge.Seconds())
	}
	c.Cookie(ck)
}

func faAppName(app faApp) string {
	if app.Name != "" {
		return app.Name
	}
	return app.Host
}

// faAppHost is the registered app the request came in on; /.mokey/* is
// answered only there
func (r *Router) faAppHost(c fiber.Ctx) (faApp, bool) {
	return r.forwardAuth.App(strings.ToLower(c.Host()))
}

func (r *Router) faPage(c fiber.Ctx, status int, icon, title, message string, vars fiber.Map) error {
	if vars == nil {
		vars = fiber.Map{}
	}
	vars["icon"], vars["title"], vars["message"] = icon, title, message
	return c.Status(status).Render("forward-auth-denied.html", vars)
}

func (r *Router) faExpired(c fiber.Ctx, app *faApp) error {
	msg := TC(c, "forward_auth.expired_generic")
	if app != nil {
		msg = fmt.Sprintf(TC(c, "forward_auth.expired_open_again"), faAppName(*app))
	}
	return r.faPage(c, fiber.StatusBadRequest, "fa-clock", TC(c, "forward_auth.expired_title"), msg, nil)
}

func (r *Router) faDenied(c fiber.Ctx, app faApp, reason string) error {
	name := faAppName(app)
	vars := fiber.Map{}
	var msg string
	switch reason {
	case "not_in_group":
		msg = fmt.Sprintf(TC(c, "forward_auth.denied_not_in_group"), name, strings.Join(app.Groups, ", "))
		if viper.GetBool("accounts.enable_groups") {
			vars["link"] = r.forwardAuth.URL.JoinPath("/groups").String()
			vars["link_text"] = TC(c, "forward_auth.request_group")
		}
	case "hbac_denied":
		msg = fmt.Sprintf(TC(c, "forward_auth.denied_hbac"), name)
	case "mfa_required":
		msg = fmt.Sprintf(TC(c, "forward_auth.denied_mfa"), name)
	default:
		msg = TC(c, "forward_auth.denied_account")
	}
	return r.faPage(c, fiber.StatusForbidden, "fa-lock", fmt.Sprintf(TC(c, "forward_auth.denied_title"), name), msg, vars)
}

func (r *Router) faAuditDenied(c fiber.Ctx, username string, app faApp, reason string) {
	slog.Warn("AUDIT forward-auth denied",
		"username", username,
		"app", app.Host,
		"reason", reason,
		"ip", RemoteIP(c),
	)
}

// faHop answers the cross-site arrival, which carries no SameSite=Strict
// session cookie, with a page that loads the same URL again from mokey's
// own origin. It must not read or create a session: a fresh empty session
// cookie would replace the user's real one.
func (r *Router) faHop(c fiber.Ctx) error {
	if c.Query("hop") == "1" {
		return c.Next()
	}
	next := c.OriginalURL()
	if strings.Contains(next, "?") {
		next += "&hop=1"
	} else {
		next += "?hop=1"
	}
	return c.Render("forward-auth-hop.html", fiber.Map{"next": safeNextPath(next)})
}

func faNavigation(c fiber.Ctx) bool {
	if m := c.Get("Sec-Fetch-Mode"); m != "" && m != "navigate" {
		return false
	}
	return c.Get("X-Requested-With") == "" && strings.Contains(c.Get(fiber.HeaderAccept), "text/html")
}

func (r *Router) ForwardAuthVerify(c fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	result := r.metrics.forwardAuthRequests.WithLabelValues

	orig, err := resolveOriginal(c, c.IsProxyTrusted())
	if err != nil {
		result("denied").Inc()
		return c.Status(fiber.StatusForbidden).SendString("")
	}
	app, ok := r.forwardAuth.App(orig.Host)
	if !ok {
		result("denied").Inc()
		return c.Status(fiber.StatusForbidden).SendString("")
	}

	s, err := r.faLoadSession(c.Cookies(faSessionCookie))
	if err != nil {
		return err
	}
	if s == nil || s.Host != app.Host {
		result("unauthenticated").Inc()
		if c.Get("X-Original-URL") != "" || !faNavigation(c) {
			return c.Status(fiber.StatusUnauthorized).SendString("")
		}
		orig.Scheme = "https"
		start := url.URL{Scheme: "https", Host: app.Host, Path: "/.mokey/start", RawQuery: url.Values{"rd": {orig.String()}}.Encode()}
		return c.Redirect().Status(fiber.StatusFound).To(start.String())
	}

	if now := time.Now(); now.Sub(s.CheckedAt) >= r.forwardAuth.Recheck {
		d, err := r.faAccess(s.Username, app)
		if err != nil {
			return err
		}
		if !d.Allowed {
			if err := r.faDeleteSession(s.ID); err != nil {
				slog.Error("Failed to delete app session", "username", s.Username, "app", app.Host, "err", err)
			}
			slog.Info("App session ended on recheck", "username", s.Username, "app", app.Host, "reason", d.Reason)
			result("denied").Inc()
			return r.faDenied(c, app, d.Reason)
		}
		s.Groups, s.Name, s.Email, s.CheckedAt = d.Groups, displayName(d.User), d.User.Email, now
		r.recordSignIn(s.Username, now)
	}
	if err := r.faTouch(s); err != nil {
		slog.Warn("Failed to refresh app session", "username", s.Username, "app", app.Host, "err", err)
	}

	groups := strings.Join(s.Groups, ",")
	for k, v := range map[string]string{
		"X-Auth-Request-User":               s.Username,
		"X-Auth-Request-Preferred-Username": s.Username,
		"X-Auth-Request-Email":              s.Email,
		"X-Auth-Request-Groups":             groups,
		"Remote-User":                       s.Username,
		"Remote-Email":                      s.Email,
		"Remote-Groups":                     groups,
		"Remote-Name":                       s.Name,
	} {
		c.Set(k, v)
	}
	result("allowed").Inc()
	return c.SendStatus(fiber.StatusOK)
}

// ForwardAuthStart runs on the app's host: it binds the sign-in to this
// browser with a nonce cookie there, then sends it to mokey
func (r *Router) ForwardAuthStart(c fiber.Ctx) error {
	app, ok := r.faAppHost(c)
	if !ok {
		return NotFoundHandler(c)
	}
	raw := c.Query("rd")
	if raw == "" {
		raw = "https://" + app.Host + "/"
	}
	rd, ok := validRedirect(raw, app.Host)
	if !ok {
		return fiber.ErrBadRequest
	}
	id, nonce, err := r.faNewPending(rd, app.Host)
	if err != nil {
		return err
	}
	faCookie(c, faNonceCookie, nonce, faPendingTTL)
	next := r.forwardAuth.URL.JoinPath(faContinuePath)
	next.RawQuery = url.Values{"p": {id}}.Encode()
	return c.Redirect().Status(fiber.StatusFound).To(next.String())
}

func (r *Router) ForwardAuthContinue(c fiber.Ctx) error {
	id := c.Query("p")
	p, err := r.faPeekPending(id)
	if err != nil {
		return err
	}
	if p == nil {
		return r.faExpired(c, nil)
	}
	app, ok := r.forwardAuth.App(p.Host)
	if !ok {
		return r.faExpired(c, nil)
	}

	username := r.user(c).Username
	d, err := r.faAccess(username, app)
	if err != nil {
		return err
	}
	if !d.Allowed {
		r.faAuditDenied(c, username, app, d.Reason)
		return r.faDenied(c, app, d.Reason)
	}

	sess, err := r.session(c)
	if err != nil {
		return err
	}
	code, err := r.faNewCode(faCode{Username: username, Host: app.Host, PendingID: id, ParentSID: sess.ID()})
	if err != nil {
		return err
	}
	cb := url.URL{Scheme: "https", Host: app.Host, Path: "/.mokey/callback", RawQuery: url.Values{"code": {code}, "state": {id}}.Encode()}
	return c.Redirect().Status(fiber.StatusFound).To(cb.String())
}

func (r *Router) ForwardAuthCallback(c fiber.Ctx) error {
	app, ok := r.faAppHost(c)
	if !ok {
		return NotFoundHandler(c)
	}
	code, err := r.faTakeCode(c.Query("code"))
	if err != nil {
		return err
	}
	if code == nil || code.Host != app.Host || code.PendingID != c.Query("state") {
		return r.faExpired(c, &app)
	}
	p, err := r.faTakePending(code.PendingID)
	if err != nil {
		return err
	}
	if p == nil || p.Host != app.Host {
		return r.faExpired(c, &app)
	}
	nonce := c.Cookies(faNonceCookie)
	if nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(p.Nonce)) != 1 {
		slog.Warn("Forward-auth callback without the browser's sign-in nonce", "username", code.Username, "app", app.Host, "ip", RemoteIP(c))
		return r.faPage(c, fiber.StatusForbidden, "fa-lock", TC(c, "forward_auth.expired_title"),
			fmt.Sprintf(TC(c, "forward_auth.expired_open_again"), faAppName(app)), nil)
	}
	// a code issued just before sign-out must not become an app session
	if !r.sessionAlive(code.ParentSID) {
		return r.faExpired(c, &app)
	}
	rd, ok := validRedirect(p.RD, app.Host)
	if !ok {
		return fiber.ErrBadRequest
	}

	d, err := r.faAccess(code.Username, app)
	if err != nil {
		return err
	}
	if !d.Allowed {
		r.faAuditDenied(c, code.Username, app, d.Reason)
		return r.faDenied(c, app, d.Reason)
	}
	s := &faSession{
		Username: code.Username, Host: app.Host, ParentSID: code.ParentSID,
		Groups: d.Groups, Name: displayName(d.User), Email: d.User.Email,
	}
	if err := r.faCreateSession(s); err != nil {
		return err
	}
	faCookie(c, faSessionCookie, s.ID, r.forwardAuth.SessionMax)
	faCookie(c, faNonceCookie, "", 0)
	slog.Info("AUDIT forward-auth sign-in",
		"username", s.Username,
		"app", app.Host,
		"ip", RemoteIP(c),
	)
	r.recordSignIn(s.Username, time.Now())
	// absolute: a path such as //evil.org would leave the host
	return c.Redirect().Status(fiber.StatusFound).To(rd.String())
}

// ForwardAuthSignout ends only the app session; signing out of mokey is a
// POST on mokey's own page
func (r *Router) ForwardAuthSignout(c fiber.Ctx) error {
	app, ok := r.faAppHost(c)
	if !ok {
		return NotFoundHandler(c)
	}
	if id := c.Cookies(faSessionCookie); id != "" {
		if s, err := r.faLoadSession(id); err != nil || (s != nil && s.Host == app.Host) {
			if err := r.faDeleteSession(id); err != nil {
				slog.Error("Failed to delete app session", "app", app.Host, "err", err)
			}
		}
	}
	faCookie(c, faSessionCookie, "", 0)
	next := r.forwardAuth.URL.JoinPath(faSignedOutPath)
	next.RawQuery = url.Values{"app": {app.Host}}.Encode()
	return c.Redirect().Status(fiber.StatusFound).To(next.String())
}

func (r *Router) ForwardAuthSignedOut(c fiber.Ctx) error {
	app, ok := r.forwardAuth.App(c.Query("app"))
	if !ok {
		return NotFoundHandler(c)
	}
	signedIn, _ := r.isLoggedIn(c)
	return c.Render("forward-auth-signedout.html", fiber.Map{
		"title":     fmt.Sprintf(TC(c, "forward_auth.signedout_title"), faAppName(app)),
		"signed_in": signedIn,
	})
}
