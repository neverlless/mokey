package server

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v3"
)

const faVerifyPath = "/forward-auth/verify"

// resolveOriginal returns the URL the user asked the proxy for. Forwarded
// headers count only from a trusted peer; otherwise Host and the path after
// the verify prefix are used (Envoy ext_authz, Cilium, Gateway API).
func resolveOriginal(c fiber.Ctx, trusted bool) (*url.URL, error) {
	var u *url.URL
	var err error
	if o := c.Get("X-Original-URL"); trusted && o != "" {
		if u, err = url.Parse(o); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("invalid X-Original-URL")
		}
	} else if h := c.Get("X-Forwarded-Host"); trusted && h != "" {
		proto := c.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = "https"
		}
		if proto != "http" && proto != "https" {
			return nil, fmt.Errorf("invalid X-Forwarded-Proto")
		}
		uri := c.Get("X-Forwarded-Uri")
		if uri == "" || uri[0] != '/' {
			uri = "/" + uri
		}
		if u, err = url.Parse(proto + "://" + h + uri); err != nil || u.Host != h {
			return nil, fmt.Errorf("invalid X-Forwarded-Host or X-Forwarded-Uri")
		}
	} else {
		rest := strings.TrimPrefix(c.OriginalURL(), faVerifyPath)
		if rest == "" || rest[0] != '/' && rest[0] != '?' {
			rest = "/" + rest
		}
		host := string(c.Request().Host())
		if host == "" {
			return nil, fmt.Errorf("missing Host")
		}
		if u, err = url.Parse("https://" + host + rest); err != nil || u.Host != host {
			return nil, fmt.Errorf("invalid Host or path")
		}
	}
	u.Host = strings.ToLower(u.Host)
	u.User, u.Fragment = nil, ""
	return u, nil
}

// validRedirect accepts only an absolute https URL on exactly host.
func validRedirect(raw, host string) (*url.URL, bool) {
	if strings.Contains(raw, `\`) || strings.IndexFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || !strings.EqualFold(u.Host, host) {
		return nil, false
	}
	u.Host = strings.ToLower(u.Host)
	return u, true
}
