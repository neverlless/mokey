package server

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	hydra "github.com/ory/hydra-client-go/v26"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

type Router struct {
	adminClient  *ipa.Client
	sessionStore *session.Store
	emailer      *Emailer
	storage      fiber.Storage

	// Hydra consent app support
	hydraClient *hydra.APIClient

	// Prometheus metrics
	metrics *Metrics
}

func NewRouter(storage fiber.Storage) (*Router, error) {
	r := &Router{
		storage: storage,
	}

	log.AddHook(NewAuditHook(storage))

	r.adminClient = newIPAClient()

	err := ipaKeytabLogin(r.adminClient, viper.GetString("site.keytab"), viper.GetString("site.ktuser"))
	if err != nil {
		return nil, err
	}

	r.adminClient.StickySession(false)

	r.sessionStore = session.New(session.Config{
		Storage:        storage,
		Expiration:     time.Duration(viper.GetInt("server.session_idle_timeout")) * time.Second,
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
			log.Fatal(err)
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
func RemoteIP(c *fiber.Ctx) string {
	peer := c.Context().RemoteIP()
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

func (r *Router) SetupRoutes(app *fiber.App) {
	// Health check (no auth, no CSRF/session - must be registered first)
	app.Get("/healthz", r.Healthz)

	// CSRF tokens stored in sessions
	app.Use(r.CSRF)

	app.Get("/", r.RequireLogin, r.Index)
	app.Get("/account", r.RequireLogin, r.Index)
	app.Get("/password", r.RequireLogin, r.Index)
	app.Get("/security", r.RequireLogin, r.Index)
	app.Get("/sshkey", r.RequireLogin, r.Index)
	app.Get("/passkey", r.RequireLogin, r.Index)
	app.Get("/otp", r.RequireLogin, r.Index)
	app.Get("/groups", r.RequireLogin, r.Index)
	app.Get("/access", r.RequireLogin, r.Index)
	app.Post("/access/test", r.RequireLogin, r.RequireHTMX, r.AccessTest)

	// Subordinate IDs
	if viper.GetBool("accounts.enable_subid") {
		app.Post("/subid/generate", r.RequireLogin, r.RequireHTMX, r.SubidGenerate)
	}

	app.Post("/groups/request", r.RequireLogin, r.RequireHTMX, r.GroupRequestJoin)
	app.Post("/groups/leave", r.RequireLogin, r.RequireHTMX, r.GroupRequestLeave)
	app.Post("/groups/approve", r.RequireLogin, r.RequireHTMX, r.GroupApprove)
	app.Post("/groups/deny", r.RequireLogin, r.RequireHTMX, r.GroupDeny)
	app.Post("/groups/remove-member", r.RequireLogin, r.RequireHTMX, r.GroupRemoveMember)

	// Account Create
	if viper.GetBool("accounts.enable_signup") {
		app.Get("/signup", r.RequireNoLogin, r.AccountCreate)
		app.Post("/signup", r.RequireNoLogin, r.AccountCreate)
	}

	// Auth
	app.Get("/auth/login", r.RequireNoLogin, r.Login)
	app.Post("/auth/login", r.RequireNoLogin, r.CheckUser)
	app.Post("/auth/authenticate", r.RequireNoLogin, r.Authenticate)
	app.Post("/auth/expiredpw", r.RequireNoLogin, r.PasswordExpired)
	app.Get("/auth/forgotpw", r.RequireNoLogin, r.PasswordForgot)
	app.Post("/auth/forgotpw", r.RequireNoLogin, r.PasswordForgot)
	app.Get("/auth/forgotuser", r.RequireNoLogin, r.UsernameForgot)
	app.Post("/auth/forgotuser", r.RequireNoLogin, r.UsernameForgot)
	app.Get("/auth/verify", r.RequireNoLogin, r.AccountVerifyResend)
	app.Post("/auth/verify", r.RequireNoLogin, r.AccountVerifyResend)
	app.Get("/auth/resetpw/:token", r.PasswordReset)
	app.Post("/auth/resetpw/:token", r.PasswordReset)
	app.Get("/auth/verify/:token", r.AccountVerify)
	app.Post("/auth/verify/:token", r.AccountVerify)
	app.Get("/auth/otprecovery", r.RequireNoLogin, r.OTPRecoveryRequest)
	app.Post("/auth/otprecovery", r.RequireNoLogin, r.OTPRecoveryRequest)
	app.Get("/auth/otprecovery/:token", r.OTPRecoveryConfirm)
	app.Post("/auth/otprecovery/:token", r.OTPRecoveryConfirm)
	app.Post("/auth/logout", r.Logout)
	// Hydra redirects the browser here with a logout_challenge (OIDC logout)
	app.Get("/auth/logout", r.Logout)
	app.Get("/auth/captcha/:id.png", r.Captcha)

	// Account Settings
	app.Get("/account/settings", r.RequireLogin, r.RequireHTMX, r.AccountSettings)
	app.Post("/account/settings", r.RequireLogin, r.RequireHTMX, r.AccountSettings)
	app.Get("/auth/email/confirm/:token", r.EmailChangeConfirm)
	app.Post("/auth/email/confirm/:token", r.EmailChangeConfirm)

	// Password
	app.Get("/password/change", r.RequireLogin, r.RequireHTMX, r.PasswordChange)
	app.Post("/password/change", r.RequireLogin, r.RequireHTMX, r.PasswordChange)

	// Security
	app.Get("/security/settings", r.RequireLogin, r.RequireHTMX, r.SecurityList)
	app.Post("/security/session/revoke", r.RequireLogin, r.RequireHTMX, r.SessionRevoke)
	app.Post("/security/sessions/revoke-others", r.RequireLogin, r.RequireHTMX, r.SessionRevokeOthers)
	app.Post("/security/mfa/enable", r.RequireLogin, r.RequireHTMX, r.TwoFactorEnable)
	app.Post("/security/mfa/disable", r.RequireLogin, r.RequireHTMX, r.TwoFactorDisable)

	// SSH Keys
	// Admin
	app.Get("/admin", r.RequireLogin, r.Index)
	app.Post("/admin/invite", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.InviteSend)
	app.Get("/admin/users", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminUserList)
	app.Get("/admin/pending", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminPendingList)
	app.Get("/admin/otprecovery", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminOTPRecoveryList)
	app.Get("/admin/audit", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminAuditList)
	app.Post("/admin/user/:action", r.RequireLogin, r.RequireAdmin, r.RequireHTMX, r.AdminUserAction)
	app.Get("/auth/invite/:token", r.RequireNoLogin, r.InviteAccept)
	app.Post("/auth/invite/:token", r.RequireNoLogin, r.InviteAccept)

	// Passkeys
	app.Post("/passkey/begin", r.RequireLogin, r.PasskeyBegin)
	app.Post("/passkey/finish", r.RequireLogin, r.PasskeyFinish)
	app.Post("/passkey/remove", r.RequireLogin, r.RequireHTMX, r.PasskeyRemove)

	app.Get("/sshkey/list", r.RequireLogin, r.RequireHTMX, r.SSHKeyList)
	app.Get("/sshkey/modal", r.RequireLogin, r.RequireHTMX, r.SSHKeyModal)
	app.Post("/sshkey/add", r.RequireLogin, r.RequireMFA, r.RequireHTMX, r.SSHKeyAdd)
	app.Post("/sshkey/remove", r.RequireLogin, r.RequireMFA, r.RequireHTMX, r.SSHKeyRemove)

	// OTP Tokens
	app.Get("/otptoken/list", r.RequireLogin, r.RequireHTMX, r.OTPTokenList)
	app.Get("/otptoken/modal", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenModal)
	app.Post("/otptoken/add", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenAdd)
	app.Post("/otptoken/verify", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenVerify)
	app.Post("/otptoken/remove", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenRemove)
	app.Post("/otptoken/enable", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenEnable)
	app.Post("/otptoken/disable", r.RequireLogin, r.RequireHTMX, r.RequireOTPSelfService, r.OTPTokenDisable)

	if viper.IsSet("site.logo") {
		app.Get("/images/logo", r.Logo)
	}

	if viper.IsSet("site.css") {
		app.Get("/css/styles", r.Styles)
	}

	if viper.IsSet("hydra.admin_url") {
		app.Get("/oauth/consent", r.ConsentGet)
		app.Get("/oauth/login", r.LoginOAuthGet)
		app.Get("/oauth/error", r.HydraError)
		app.Post("/security/apps/revoke", r.RequireLogin, r.RequireHTMX, r.AppRevoke)
	}

	// Prometheus metrics
	if viper.GetBool("server.enable_metrics") {
		app.Get("/metrics", r.Metrics)
	}
}

func (r *Router) userClient(c *fiber.Ctx) *ipa.Client {
	return c.Locals(ContextKeyIPAClient).(*ipa.Client)
}

func (r *Router) username(c *fiber.Ctx) string {
	return c.Locals(ContextKeyUsername).(string)
}

func (r *Router) user(c *fiber.Ctx) *ipa.User {
	return c.Locals(ContextKeyUser).(*ipa.User)
}

func (r *Router) Index(c *fiber.Ctx) error {
	user := r.user(c)

	path := strings.TrimPrefix(c.Path(), "/")
	if path == "" {
		path = "account"
	}

	vars := fiber.Map{
		"user":     user,
		"path":     path,
		"is_admin": isAdmin(user),
	}
	expiryWarningVars(user, vars)

	if path == "admin" && !isAdmin(user) {
		return c.Status(fiber.StatusForbidden).SendString("")
	}

	if path == "account" && viper.GetBool("accounts.enable_subid") {
		r.subidVars(user.Username, vars)
	}

	if path == "groups" {
		r.groupsVars(c, vars)
	}

	if path == "access" {
		r.accessVars(c, vars)
	}

	if path == "sshkey" {
		vars["keys"] = user.SSHAuthKeys
	} else if path == "security" {
		r.securityVars(c, vars)
	} else if path == "passkey" {
		passkeys, err := r.passkeyList(c)
		if err != nil {
			log.WithFields(log.Fields{
				"username": r.username(c),
				"err":      err,
			}).Error("Failed to fetch passkeys from FreeIPA")
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

func (r *Router) Logo(c *fiber.Ctx) error {
	if viper.IsSet("site.logo") {
		return c.SendFile(viper.GetString("site.logo"))
	}

	return c.Status(fiber.StatusNotFound).SendString("")
}

func (r *Router) Styles(c *fiber.Ctx) error {
	if viper.IsSet("site.css") {
		return c.SendFile(viper.GetString("site.css"))
	}

	return c.Status(fiber.StatusNotFound).SendString("")
}

func (r *Router) Metrics(c *fiber.Ctx) error {
	return r.metrics.Handler(c)
}
