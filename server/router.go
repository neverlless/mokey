package server

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	ipa "github.com/neverlless/goipa"
	hydra "github.com/ory/hydra-client-go/v26"
	"github.com/spf13/viper"
)

type Router struct {
	adminClient  *ipa.Client
	sessionStore *session.Store
	emailer      *Emailer
	storage      fiber.Storage
	lock         *storeLock
	groupExpiry  *groupExpiryConfig
	expiryFails  expiryFailureSet

	// Hydra consent app support
	hydraClient *hydra.APIClient

	// Prometheus metrics
	metrics *Metrics

	// bg tracks fire-and-forget notification goroutines spawned by
	// handlers, so tests can wait for them to finish before the next
	// test resets shared state (e.g. global viper config).
	bg sync.WaitGroup
}

// goBG runs fn in a tracked goroutine (see bg above).
func (r *Router) goBG(fn func()) {
	r.bg.Add(1)
	go func() {
		defer r.bg.Done()
		fn()
	}()
}

func NewRouter(storage fiber.Storage) (*Router, error) {
	r := &Router{
		storage: storage,
		lock:    newStoreLock(storage),
	}

	var err error
	r.groupExpiry, err = loadGroupExpiryConfig()
	if err != nil {
		return nil, err
	}
	if msg := groupExpiryWarning(r.groupExpiry); msg != "" {
		slog.Warn(msg)
	}
	if r.groupExpiry.Enabled() {
		r.warnRedisEviction()
	}

	hooks, err := newWebhooks()
	if err != nil {
		return nil, err
	}
	audit := NewAuditHandler(NewLogHandler(os.Stderr), storage)
	audit.hooks = hooks
	slog.SetDefault(slog.New(audit))

	r.adminClient, err = newIPAClient()
	if err != nil {
		return nil, err
	}

	err = ipaKeytabLogin(r.adminClient, viper.GetString("site.keytab"), viper.GetString("site.ktuser"))
	if err != nil {
		return nil, err
	}

	r.adminClient.StickySession(false)

	r.sessionStore = session.NewStore(session.Config{
		Storage:        storage,
		IdleTimeout:    time.Duration(viper.GetInt("server.session_idle_timeout")) * time.Second,
		CookieSameSite: "Strict",
		CookieSecure:   viper.GetBool("server.secure_cookies"),
		CookieHTTPOnly: true,
	})

	r.emailer, err = NewEmailer(storage)
	if err != nil {
		return nil, err
	}

	if viper.IsSet("hydra.admin_url") {
		adminURL, err := url.Parse(viper.GetString("hydra.admin_url"))
		if err != nil {
			return nil, fmt.Errorf("hydra.admin_url: %w", err)
		}

		cfg := hydra.NewConfiguration()
		cfg.Servers = hydra.ServerConfigurations{{URL: adminURL.String()}}
		if viper.GetBool("hydra.fake_tls_termination") {
			cfg.HTTPClient = &http.Client{
				Transport: &FakeTLSTransport{T: http.DefaultTransport},
			}
		}

		r.hydraClient = hydra.NewAPIClient(cfg)
	}

	r.metrics = NewMetrics()

	return r, nil
}

func trustedProxyContains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, t := range viper.GetStringSlice("server.trusted_proxies") {
		if strings.Contains(t, "/") {
			if _, ipnet, err := net.ParseCIDR(t); err == nil && ipnet.Contains(ip) {
				return true
			}
		} else if p := net.ParseIP(t); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}

// RemoteIP returns the client address used for rate limiting and audit
// logging. X-Forwarded-For is only consulted when the direct peer is a
// configured trusted proxy (server.trusted_proxies), and entries are walked
// right to left skipping further trusted proxies — the leftmost values are
// client-supplied and forgeable.
func RemoteIP(c fiber.Ctx) string {
	peer := c.RequestCtx().RemoteIP()
	if !trustedProxyContains(peer) {
		return peer.String()
	}

	ips := c.IPs()
	for i := len(ips) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(ips[i]))
		if ip == nil {
			continue
		}
		if !trustedProxyContains(ip) {
			return ip.String()
		}
	}

	return peer.String()
}

// get registers a GET route and its HEAD twin in place, as Fiber v2's
// app.Get did. Fiber v3's automatic HEAD routes are appended after the
// catch-all 404 handler and after CSRF, which would answer HEAD with 404 and
// give /healthz probes a session.
func get(app *fiber.App, path string, handler any, handlers ...any) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, path, handler, handlers...)
}

func (r *Router) SetupRoutes(app *fiber.App) {
	// Health check (no auth, no CSRF/session - must be registered first)
	get(app, "/healthz", r.Healthz)

	// Bearer-token JSON API, also ahead of CSRF: no session, no cookie
	if len(viper.GetStringSlice("api.tokens")) > 0 {
		get(app, "/api/v1/events", r.RequireAPIToken, r.APIEvents)
		get(app, "/api/v1/group-requests", r.RequireAPIToken, r.APIGroupRequests)
		get(app, "/api/v1/otp-recovery", r.RequireAPIToken, r.APIOTPRecovery)
	}

	// CSRF tokens stored in sessions
	app.Use(r.CSRF)

	get(app, "/", r.RequireLogin, r.Index)
	get(app, "/account", r.RequireLogin, r.Index)
	get(app, "/password", r.RequireLogin, r.Index)
	get(app, "/security", r.RequireLogin, r.Index)
	get(app, "/sshkey", r.RequireLogin, r.Index)
	get(app, "/passkey", r.RequireLogin, r.Index)
	get(app, "/otp", r.RequireLogin, r.Index)
	// Group self-service and the access page are whole features an operator
	// can switch off; hiding the tab is not enough, the routes go too (#27)
	if viper.GetBool("accounts.enable_groups") {
		get(app, "/groups", r.RequireLogin, r.Index)
		app.Post("/groups/request", r.RequireLogin, r.RequireHTMX, r.GroupRequestJoin)
		app.Post("/groups/leave", r.RequireLogin, r.RequireHTMX, r.GroupRequestLeave)
		app.Post("/groups/renew", r.RequireLogin, r.RequireHTMX, r.GroupRequestRenew)
		app.Post("/groups/approve", r.RequireLogin, r.RequireHTMX, r.GroupApprove)
		app.Post("/groups/deny", r.RequireLogin, r.RequireHTMX, r.GroupDeny)
		app.Post("/groups/remove-member", r.RequireLogin, r.RequireHTMX, r.GroupRemoveMember)
	}

	if viper.GetBool("accounts.enable_access") {
		get(app, "/access", r.RequireLogin, r.Index)
		app.Post("/access/test", r.RequireLogin, r.RequireHTMX, r.AccessTest)
	}

	if viper.GetBool("accounts.enable_apps") && viper.IsSet("hydra.admin_url") {
		get(app, "/apps", r.RequireLogin, r.Index)
		if viper.GetBool("accounts.enable_groups") {
			app.Post("/apps/request", r.RequireLogin, r.RequireHTMX, r.AppRequest)
		}
	}

	// Subordinate IDs
	if viper.GetBool("accounts.enable_subid") {
		app.Post("/subid/generate", r.RequireLogin, r.RequireHTMX, r.SubidGenerate)
	}

	// Account Create
	if viper.GetBool("accounts.enable_signup") {
		get(app, "/signup", r.RequireNoLogin, r.AccountCreate)
		app.Post("/signup", r.RequireNoLogin, r.AccountCreate)
	}

	// Auth
	get(app, "/auth/login", r.RequireNoLogin, r.Login)
	app.Post("/auth/login", r.RequireNoLogin, r.CheckUser)
	app.Post("/auth/authenticate", r.RequireNoLogin, r.Authenticate)
	app.Post("/auth/expiredpw", r.RequireNoLogin, r.PasswordExpired)
	get(app, "/auth/forgotpw", r.RequireNoLogin, r.PasswordForgot)
	app.Post("/auth/forgotpw", r.RequireNoLogin, r.PasswordForgot)
	get(app, "/auth/forgotuser", r.RequireNoLogin, r.UsernameForgot)
	app.Post("/auth/forgotuser", r.RequireNoLogin, r.UsernameForgot)
	get(app, "/auth/verify", r.RequireNoLogin, r.AccountVerifyResend)
	app.Post("/auth/verify", r.RequireNoLogin, r.AccountVerifyResend)
	get(app, "/auth/resetpw/:token", r.PasswordReset)
	app.Post("/auth/resetpw/:token", r.PasswordReset)
	get(app, "/auth/verify/:token", r.AccountVerify)
	app.Post("/auth/verify/:token", r.AccountVerify)
	get(app, "/auth/otprecovery", r.RequireNoLogin, r.OTPRecoveryRequest)
	app.Post("/auth/otprecovery", r.RequireNoLogin, r.OTPRecoveryRequest)
	get(app, "/auth/otprecovery/:token", r.OTPRecoveryConfirm)
	app.Post("/auth/otprecovery/:token", r.OTPRecoveryConfirm)
	app.Post("/auth/logout", r.Logout)
	// Hydra redirects the browser here with a logout_challenge (OIDC logout)
	get(app, "/auth/logout", r.Logout)
	get(app, "/auth/captcha/:id.png", r.Captcha)

	// Account Settings
	get(app, "/account/settings", r.RequireLogin, r.RequireHTMX, r.AccountSettings)
	app.Post("/account/settings", r.RequireLogin, r.RequireHTMX, r.AccountSettings)
	get(app, "/auth/email/confirm/:token", r.EmailChangeConfirm)
	app.Post("/auth/email/confirm/:token", r.EmailChangeConfirm)

	// Password
	get(app, "/password/change", r.RequireLogin, r.RequireHTMX, r.PasswordChange)
	app.Post("/password/change", r.RequireLogin, r.RequireHTMX, r.PasswordChange)

	// Security
	get(app, "/security/settings", r.RequireLogin, r.RequireHTMX, r.SecurityList)
	app.Post("/security/session/revoke", r.RequireLogin, r.RequireHTMX, r.SessionRevoke)
	app.Post("/security/sessions/revoke-others", r.RequireLogin, r.RequireHTMX, r.SessionRevokeOthers)
	app.Post("/security/mfa/enable", r.RequireLogin, r.RequireHTMX, r.TwoFactorEnable)
	app.Post("/security/mfa/disable", r.RequireLogin, r.RequireHTMX, r.TwoFactorDisable)

	// SSH Keys
	// Admin
	get(app, "/admin", r.RequireLogin, r.Index)
	get(app, "/admin/people", r.RequireLogin, r.Index)
	get(app, "/admin/log", r.RequireLogin, r.Index)
	app.Post("/admin/invite", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.InviteSend)
	get(app, "/admin/users", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminUserList)
	get(app, "/admin/pending", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminPendingList)
	get(app, "/admin/otprecovery", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminOTPRecoveryList)
	get(app, "/admin/audit", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminAuditList)
	get(app, "/admin/helpdesk", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminHelpdesk)
	app.Post("/admin/user/:action", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminUserAction)
	get(app, "/auth/invite/:token", r.RequireNoLogin, r.InviteAccept)
	app.Post("/auth/invite/:token", r.RequireNoLogin, r.InviteAccept)

	// Passkeys
	app.Post("/passkey/begin", r.RequireLogin, r.PasskeyBegin)
	app.Post("/passkey/finish", r.RequireLogin, r.PasskeyFinish)
	app.Post("/passkey/remove", r.RequireLogin, r.RequireHTMX, r.PasskeyRemove)

	get(app, "/sshkey/list", r.RequireLogin, r.RequireHTMX, r.SSHKeyList)
	get(app, "/sshkey/modal", r.RequireLogin, r.RequireHTMX, r.SSHKeyModal)
	app.Post("/sshkey/add", r.RequireLogin, r.RequireMFA, r.RequireHTMX, r.SSHKeyAdd)
	app.Post("/sshkey/remove", r.RequireLogin, r.RequireMFA, r.RequireHTMX, r.SSHKeyRemove)

	// OTP Tokens
	get(app, "/otptoken/list", r.RequireLogin, r.RequireHTMX, r.OTPTokenList)
	get(app, "/otptoken/modal", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenModal)
	app.Post("/otptoken/add", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenAdd)
	app.Post("/otptoken/verify", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenVerify)
	app.Post("/otptoken/remove", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenRemove)
	app.Post("/otptoken/enable", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenEnable)
	app.Post("/otptoken/disable", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenDisable)

	if viper.IsSet("site.logo") {
		get(app, "/images/logo", r.Logo)
	}

	if viper.IsSet("site.css") {
		get(app, "/css/styles", r.Styles)
	}

	if viper.IsSet("hydra.admin_url") {
		get(app, "/oauth/consent", r.ConsentGet)
		get(app, "/oauth/login", r.LoginOAuthGet)
		get(app, "/oauth/error", r.HydraError)
		app.Post("/security/apps/revoke", r.RequireLogin, r.RequireHTMX, r.AppRevoke)
	}

	// Prometheus metrics
	if viper.GetBool("server.enable_metrics") {
		get(app, "/metrics", r.Metrics)
	}
}

func (r *Router) userClient(c fiber.Ctx) *ipa.Client {
	return c.Locals(ContextKeyIPAClient).(*ipa.Client)
}

func (r *Router) username(c fiber.Ctx) string {
	return c.Locals(ContextKeyUsername).(string)
}

func (r *Router) user(c fiber.Ctx) *ipa.User {
	return c.Locals(ContextKeyUser).(*ipa.User)
}

// navSection maps a page path to the sidebar entry that owns it
func navSection(path string) string {
	switch path {
	case "admin/people":
		return "people"
	case "admin/log":
		return "log"
	case "password", "otp", "passkey", "security":
		return "security"
	}
	return path
}

func displayName(u *ipa.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if n := strings.TrimSpace(u.First + " " + u.Last); n != "" {
		return n
	}
	return u.Username
}

func initials(u *ipa.User) string {
	if u == nil {
		return ""
	}
	var s string
	for _, n := range []string{u.First, u.Last} {
		for _, r := range n {
			s += string(r)
			break
		}
	}
	if s == "" {
		for _, r := range u.Username {
			s = string(r)
			break
		}
	}
	return strings.ToUpper(s)
}

func (r *Router) Index(c fiber.Ctx) error {
	user := r.user(c)

	path := strings.TrimPrefix(c.Path(), "/")
	if path == "" {
		path = "account"
	}

	vars := fiber.Map{
		"user":         user,
		"path":         path,
		"is_admin":     isAdmin(user),
		"shell":        true,
		"section":      navSection(path),
		"initials":     initials(user),
		"display_name": displayName(user),
	}
	expiryWarningVars(user, vars)

	if strings.HasPrefix(path, "admin") && !isAdmin(user) {
		return c.Status(fiber.StatusForbidden).SendString("")
	}

	if path == "account" && viper.GetBool("accounts.enable_subid") {
		r.subidVars(user.Username, vars)
	}

	if path == "groups" {
		r.groupsVars(c, vars)
	}

	if path == "admin" {
		vars["expiry_failures"] = r.expiryFailures()
	}

	if path == "access" {
		r.accessVars(c, vars)
	}

	if path == "apps" {
		r.appsVars(c, vars)
	}

	if path == "password" {
		if msg := r.passwordElsewhere(requestLanguage(c), user); msg != "" {
			vars["password_elsewhere"] = msg
		} else {
			r.pwPolicyVars(user.Username, vars)
		}
	}

	if path == "sshkey" {
		vars["keys"] = user.SSHAuthKeys
	} else if path == "security" {
		r.securityVars(c, vars)
	} else if path == "passkey" {
		passkeys, err := r.passkeyList(c)
		if err != nil {
			slog.Error("Failed to fetch passkeys from FreeIPA",
				"username", r.username(c),
				"err", err,
			)
		}
		vars["passkeys"] = passkeys
	} else if path == "otp" {
		username := r.username(c)
		client := r.userClient(c)

		tokens, err := client.FetchOTPTokens(username)
		if err != nil {
			return err
		}

		vars["otptokens"] = tokens
	}

	return c.Render("index.html", vars)
}

func (r *Router) Logo(c fiber.Ctx) error {
	if viper.IsSet("site.logo") {
		return c.SendFile(viper.GetString("site.logo"), fiber.SendFile{ByteRange: true})
	}

	return c.Status(fiber.StatusNotFound).SendString("")
}

func (r *Router) Styles(c fiber.Ctx) error {
	if viper.IsSet("site.css") {
		return c.SendFile(viper.GetString("site.css"), fiber.SendFile{ByteRange: true})
	}

	return c.Status(fiber.StatusNotFound).SendString("")
}

func (r *Router) Metrics(c fiber.Ctx) error {
	return r.metrics.Handler(c)
}
