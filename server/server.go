package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/favicon"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	frecover "github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/gofiber/storage/memory/v2"
	"github.com/gofiber/storage/redis/v3"
	"github.com/gofiber/storage/sqlite3/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

const (
	DefaultPort = 80
)

//go:embed templates/static
var staticFS embed.FS

type Server struct {
	ListenAddress string
	Scheme        string
	KeyFile       string
	CertFile      string
	app           *fiber.App
}

func SetDefaults() {
	viper.SetDefault("site.name", "Acme Widgets")
	viper.SetDefault("site.default_language", "english")
	viper.SetDefault("site.ktuser", "mokeyapp")
	viper.SetDefault("accounts.enable_signup", true)
	viper.SetDefault("accounts.staged_signup", false)
	viper.SetDefault("accounts.enable_groups", true)
	viper.SetDefault("accounts.enable_access", true)
	viper.SetDefault("accounts.enable_apps", false)
	viper.SetDefault("accounts.enable_subid", false)
	viper.SetDefault("accounts.enable_captcha", true)
	viper.SetDefault("groups.allow_permanent", true)
	viper.SetDefault("admin.enabled", false)
	viper.SetDefault("admin.group", "admins")
	viper.SetDefault("admin.inactive_days", 90)
	viper.SetDefault("accounts.single_page_login", false)
	viper.SetDefault("accounts.hide_invalid_username_error", false)
	viper.SetDefault("accounts.default_homedir", "/home")
	viper.SetDefault("accounts.default_shell", "/bin/bash")
	viper.SetDefault("accounts.allow_change_shell", false)
	viper.SetDefault("accounts.allowed_shells", []string{"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/fish", "/sbin/nologin"})
	viper.SetDefault("accounts.min_passwd_len", 8)
	viper.SetDefault("accounts.min_passwd_classes", 2)
	viper.SetDefault("accounts.check_breached_passwords", false)
	viper.SetDefault("accounts.otp_hash_algorithm", "sha1")
	viper.SetDefault("accounts.username_from_email", false)
	viper.SetDefault("accounts.require_mfa", false)
	viper.SetDefault("accounts.require_admin_verify", false)
	viper.SetDefault("email.token_max_age", 3600)
	viper.SetDefault("email.resend_cooldown", 180)
	viper.SetDefault("accounts.password_expiry_warning_days", 14)
	viper.SetDefault("email.smtp_host", "localhost")
	viper.SetDefault("email.smtp_port", 25)
	viper.SetDefault("email.smtp_tls", "off")
	viper.SetDefault("email.from", "support@example.com")
	viper.SetDefault("server.secure_cookies", true)
	viper.SetDefault("server.session_idle_timeout", 900)
	viper.SetDefault("server.listen", "0.0.0.0:8866")
	viper.SetDefault("server.read_timeout", 5)
	viper.SetDefault("server.write_timeout", 5)
	viper.SetDefault("server.idle_timeout", 120)
	viper.SetDefault("server.rate_limit_expiration", 3600)
	viper.SetDefault("server.rate_limit_max", 10)
	viper.SetDefault("server.read_buffer_size", 16384)
	viper.SetDefault("storage.driver", "memory")
	viper.SetDefault("hydra.consent_sweep_interval", "1h")
}

func NewServer(address string) (*Server, error) {
	s := &Server{}
	s.ListenAddress = address

	app, _, err := newFiber()
	if err != nil {
		return nil, err
	}

	s.app = app

	return s, nil
}

func getAssetsFS() fs.FS {
	staticLocalPath := viper.GetString("site.static_assets_dir")
	if staticLocalPath != "" {
		slog.Debug("Using local static assets dir", "path", staticLocalPath)
		return os.DirFS(staticLocalPath)
	}

	fsys, err := fs.Sub(staticFS, "templates/static")
	if err != nil {
		slog.Error("Failed to load embedded static assets", "err", err)
		os.Exit(1)
	}

	return fsys
}

func newStorage() (storage fiber.Storage, err error) {
	// url.Parse errors quote the whole URL, password included
	defer func() {
		if u := viper.GetString("storage.redis.url"); err != nil && u != "" {
			err = errors.New(strings.ReplaceAll(err.Error(), u, redactURL(u)))
		}
	}()

	if viper.IsSet("storage.sqlite3.dbpath") && viper.GetString("storage.driver") == "memory" {
		viper.Set("storage.driver", "sqlite3")
	}

	var redisTLS *tls.Config
	if viper.GetString("storage.driver") == "redis" {
		if redisTLS, err = redisTLSConfig(viper.GetString("storage.redis.url")); err != nil {
			return nil, fmt.Errorf("storage.redis: %w", err)
		}
	}

	// the storage drivers panic when they cannot connect
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to initialize storage driver %s: %v", viper.GetString("storage.driver"), r)
		}
	}()
	switch viper.GetString("storage.driver") {
	case "sqlite3":
		storage = sqlite3.New(sqlite3.Config{
			Database: viper.GetString("storage.sqlite3.dbpath"),
			Table:    "mokey_data",
		})
	case "redis":
		storage = redis.New(redis.Config{
			URL:       viper.GetString("storage.redis.url"),
			TLSConfig: redisTLS,
			Reset:     false,
		})

	default:
		storage = memory.New()
	}

	return storage, nil
}

// redisTLSConfig builds the TLS config for a private CA and/or client
// certificate. nil when neither is set, leaving TLS to the URL scheme.
// Setting either turns TLS on even for a redis:// URL.
func redisTLSConfig(redisURL string) (*tls.Config, error) {
	caFile := viper.GetString("storage.redis.ca_file")
	certFile := viper.GetString("storage.redis.cert_file")
	keyFile := viper.GetString("storage.redis.key_file")
	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("cert_file and key_file must be set together")
	}

	opts, err := goredis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}
	cfg := opts.TLSConfig
	if cfg == nil {
		host, _, err := net.SplitHostPort(opts.Addr)
		if err != nil {
			return nil, fmt.Errorf("TLS needs a host:port url: %w", err)
		}
		cfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}

	if caFile != "" {
		pem, err := os.ReadFile(filepath.Clean(caFile))
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file: no PEM certificates in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("cert_file/key_file: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

func newFiber() (*fiber.App, *Router, error) {
	if err := LoadTranslations(); err != nil {
		return nil, nil, err
	}

	engine, err := NewTemplateRenderer()
	if err != nil {
		return nil, nil, err
	}

	storage, err := newStorage()
	if err != nil {
		return nil, nil, err
	}

	app := fiber.New(fiber.Config{
		CaseSensitive:  true,
		StrictRouting:  true,
		ReadTimeout:    time.Duration(viper.GetInt("server.read_timeout")) * time.Second,
		WriteTimeout:   time.Duration(viper.GetInt("server.write_timeout")) * time.Second,
		IdleTimeout:    time.Duration(viper.GetInt("server.idle_timeout")) * time.Second,
		ReadBufferSize: viper.GetInt("server.read_buffer_size"),
		AppName:        "mokey",
		// background notifications keep form values after the handler
		// returns; without this they alias fasthttp's reused request buffer
		Immutable:         true,
		PassLocalsToViews: true,
		ErrorHandler:      HTTPErrorHandler,
		Views:             engine,
		// mokey sends no flash messages; skip the fiber_flash cookie on every request
		DisableFlashMessages: true,
		// Only honor X-Forwarded-* headers (c.Scheme, c.Host) when
		// the request comes from a configured trusted proxy
		TrustProxy:       true,
		TrustProxyConfig: fiber.TrustProxyConfig{Proxies: viper.GetStringSlice("server.trusted_proxies")},
	})

	app.Use(frecover.New())
	app.Use(SecureHeaders)
	app.Use(SetLanguage)

	app.Use(limiter.New(limiter.Config{
		Max:                    viper.GetInt("server.rate_limit_max"),
		Expiration:             time.Duration(viper.GetInt("server.rate_limit_expiration")) * time.Second,
		SkipSuccessfulRequests: true,
		Storage:                storage,
		LimitReached:           LimitReachedHandler,
		// Key on the non-forgeable client address — X-Forwarded-For is
		// only honored behind a configured trusted proxy (see RemoteIP)
		KeyGenerator: RemoteIP,
		Next: func(c fiber.Ctx) bool {
			// failed API token checks count, as failed logins do
			if strings.HasPrefix(c.Path(), "/api/") {
				return false
			}

			if c.Method() != fiber.MethodPost {
				return true
			}

			if c.Path() == "/signup" {
				return false
			}

			if strings.HasPrefix(c.Path(), "/auth") {
				return false
			}

			return true
		},
	}))

	router, err := NewRouter(storage)
	if err != nil {
		return nil, nil, err
	}

	router.SetupRoutes(app)
	router.StartExpiryReminders()
	router.StartConsentSweep()
	router.StartMembershipExpiry()

	assetsFS := getAssetsFS()
	app.Use("/static", static.New("", static.Config{
		FS:     assetsFS,
		Browse: false,
		MaxAge: 900,
		// fasthttp answers a directory by resetting the response, security
		// headers included; leave directories to the 404 handler
		Next: func(c fiber.Ctx) bool {
			name := strings.Trim(strings.TrimPrefix(c.Path(), "/static"), "/")
			if name == "" {
				name = "."
			}
			fi, err := fs.Stat(assetsFS, name)
			return err == nil && fi.IsDir()
		},
		// Embedded files have no modification time. A year-1 Last-Modified
		// would answer every revalidation with 304, stale after an upgrade.
		ModifyResponse: func(c fiber.Ctx) error {
			if t, err := http.ParseTime(c.GetRespHeader(fiber.HeaderLastModified)); err == nil && t.IsZero() {
				c.Response().Header.Del(fiber.HeaderLastModified)
			}
			return nil
		},
	}))

	// SendFile derives the Content-Type from the extension; the favicon
	// middleware would announce a configured .png or .svg as image/x-icon
	if custom := viper.GetString("site.favicon"); custom != "" {
		get(app, "/favicon.ico", func(c fiber.Ctx) error {
			c.Set(fiber.HeaderCacheControl, "public, max-age=31536000")
			return c.SendFile(custom, fiber.SendFile{ByteRange: true})
		})
	} else {
		app.Use(favicon.New(favicon.Config{
			File:       "images/favicon.ico",
			FileSystem: assetsFS,
		}))
	}

	// This must be last
	app.Use(NotFoundHandler)

	return app, router, nil
}

var listenConfig = fiber.ListenConfig{
	ListenerNetwork:       fiber.NetworkTCP,
	DisableStartupMessage: true,
}

func (s *Server) Serve() error {
	if s.CertFile != "" && s.KeyFile != "" {
		s.Scheme = "https"
		tlsConfig, err := s.tlsConfig()
		if err != nil {
			return err
		}

		ln, err := tls.Listen("tcp", s.ListenAddress, tlsConfig)
		if err != nil {
			return err
		}

		slog.Info("Listening", "url", s.Scheme+"://"+s.ListenAddress)
		return s.app.Listener(ln, listenConfig)
	}

	s.Scheme = "http"
	slog.Info("Listening", "url", s.Scheme+"://"+s.ListenAddress)
	if err := s.app.Listen(s.ListenAddress, listenConfig); err != nil {
		return err
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.app == nil {
		return nil
	}

	return s.app.Shutdown()
}
