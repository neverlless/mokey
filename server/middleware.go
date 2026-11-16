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
	"strings"

	"github.com/gofiber/fiber/v3"
)

func SecureHeaders(c fiber.Ctx) error {
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
	c.Set(fiber.HeaderContentSecurityPolicy,
		"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-"+nonce+"'")

	// Direct TLS or an X-Forwarded-Proto from a trusted proxy
	if c.Scheme() == "https" {
		c.Set(fiber.HeaderStrictTransportSecurity, "max-age=31536000")
	}

	if !strings.HasPrefix(c.Path(), "/static") {
		c.Set("Cache-Control", "no-store")
		c.Set("Pragma", "no-cache")
	}
	return c.Next()
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
