// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

// secureHeaders adds the extra CSP sources from server.csp
func secureHeaders(csp cspExtra) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Per-request CSP nonce; templates stamp it on inline <script> tags via
		// nonce="{{ .cspNonce }}" (PassLocalsToViews). Inline styles stay
		// allowed — the templates rely on style attributes throughout.
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return err
		}
		// URL-safe alphabet: html/template would entity-escape '+' inside the
		// nonce attribute
		nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
		c.Locals("cspNonce", nonce)

		c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
		c.Set(fiber.HeaderXFrameOptions, "DENY")
		c.Set(fiber.HeaderContentSecurityPolicy, contentSecurityPolicy(nonce, "", csp))

		// Direct TLS or an X-Forwarded-Proto from a trusted proxy
		if c.Scheme() == "https" {
			c.Set(fiber.HeaderStrictTransportSecurity, "max-age=31536000")
		}

		// forward-auth pages on app hosts load these cross-origin with SRI
		if strings.HasPrefix(c.Path(), "/static/") {
			c.Set(fiber.HeaderAccessControlAllowOrigin, "*")
		}

		if !strings.HasPrefix(c.Path(), "/static") {
			c.Set("Cache-Control", "no-store")
			c.Set("Pragma", "no-cache")
		}
		return c.Next()
	}
}

// cspExtra is " src1 src2" per fetch directive, from server.csp
type cspExtra map[string]string

// CSP3 fetch directives, in the order added ones are written; the -elem and
// -attr variants are left out so script-src can't be bypassed
var cspFetchDirectives = []string{"default-src", "img-src", "style-src", "font-src", "script-src",
	"connect-src", "media-src", "object-src", "frame-src", "child-src", "worker-src", "manifest-src"}

func loadCSPExtra() (cspExtra, error) {
	x := cspExtra{}
	for name, sources := range viper.GetStringMapStringSlice("server.csp") {
		if !slices.Contains(cspFetchDirectives, name) {
			return nil, fmt.Errorf("server.csp: %q is not a fetch directive; use one of %s", name, strings.Join(cspFetchDirectives, ", "))
		}
		for _, src := range sources {
			if src == "" || strings.ContainsAny(src, ";,") || strings.IndexFunc(src, unicode.IsSpace) >= 0 {
				return nil, fmt.Errorf("server.csp: %s: %q must be a single non-empty source", name, src)
			}
			if (name == "script-src" || name == "default-src") && cspUnsafeScriptSource(src) {
				return nil, fmt.Errorf("server.csp: %s: %q would let any or inline script run", name, src)
			}
			x[name] += " " + src
		}
	}
	return x, nil
}

var cspSchemeOnly = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:(//\*)?$`)

func cspUnsafeScriptSource(src string) bool {
	src = strings.ToLower(src)
	switch src {
	case "*", "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'":
		return true
	}
	return cspSchemeOnly.MatchString(src)
}

// contentSecurityPolicy also lets assets load from assetOrigin, for mokey
// pages served on another host. A directive the base policy lacks starts
// from default-src's 'self', so adding one doesn't drop 'self'.
func contentSecurityPolicy(nonce, assetOrigin string, extra cspExtra) string {
	base := map[string]string{
		"default-src": "'self'",
		"img-src":     "'self' data:",
		"style-src":   "'self' 'unsafe-inline'",
		"script-src":  "'self' 'nonce-" + nonce + "'",
	}
	if assetOrigin != "" {
		base["img-src"] += " " + assetOrigin
		base["style-src"] += " " + assetOrigin
		base["font-src"] = "'self' " + assetOrigin
	}
	parts := make([]string, 0, len(cspFetchDirectives))
	for _, name := range cspFetchDirectives {
		v, ok := base[name]
		x, hasExtra := extra[name]
		if !ok && !hasExtra {
			continue
		}
		if !ok {
			v = "'self'"
		}
		parts = append(parts, name+" "+v+x)
	}
	return strings.Join(parts, "; ")
}

func NotFoundHandler(c fiber.Ctx) error {
	slog.Info("Requested path not found",
		"path", c.Path(),
		"ip", RemoteIP(c),
	)

	c.Status(fiber.StatusNotFound)

	if c.Get("HX-Request", "false") == "true" {
		err := c.Render("404-partial.html", nil)
		if err != nil {
			slog.Error("Failed to render custom error partial",
				"error", err,
			)
			return c.SendString("")
		}
		return nil
	}

	return c.Render("404.html", fiber.Map{})
}

func HTTPErrorHandler(c fiber.Ctx, err error) error {
	username, _ := c.Locals(ContextKeyUsername).(string)
	path := c.Path()
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	level := slog.LevelError
	if code < fiber.StatusInternalServerError {
		level = slog.LevelWarn
	}
	slog.Log(c, level, "Request failed",
		"err", err,
		"code", code,
		"username", username,
		"path", path,
		"ip", RemoteIP(c),
	)

	c.Status(code)

	if c.Locals("NoErrorTemplate") == "true" {
		return c.SendString("")
	}

	htmx := c.Get("HX-Request", "false") == "true"
	errorPage := fmt.Sprintf("%d.html", code)
	if htmx {
		errorPage = fmt.Sprintf("%d-partial.html", code)
	}
	if !errorPages[errorPage] {
		// e.g. 408 when a client stalls past server.read_timeout
		if htmx {
			return c.SendString("")
		}
		return c.SendString(http.StatusText(code))
	}
	if err := c.Render(errorPage, nil); err != nil {
		slog.Error("Failed to render custom error page",
			"page", errorPage,
			"error", err,
		)
		return c.Status(code).SendString("")
	}

	return nil
}

var errorPages = map[string]bool{
	"401.html": true, "403.html": true, "404.html": true, "500.html": true,
	"403-partial.html": true, "404-partial.html": true, "500-partial.html": true,
}

func LimitReachedHandler(c fiber.Ctx) error {
	slog.Warn("Limit reached",
		"ip", RemoteIP(c),
	)
	return c.Status(fiber.StatusTooManyRequests).SendString("Too many requests. Please try again later.")
}

func (r *Router) RequireHTMX(c fiber.Ctx) error {
	if c.Get("HX-Request", "false") == "true" {
		return c.Next()
	}

	return c.Status(fiber.StatusBadRequest).SendString("")
}
