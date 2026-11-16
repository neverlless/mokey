package server

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func resolveVia(t *testing.T, trusted bool, host, target string, hdr map[string]string) string {
	t.Helper()
	app := fiber.New()
	var got string
	app.All("/*", func(c fiber.Ctx) error {
		u, err := resolveOriginal(c, trusted)
		if err != nil {
			return c.Status(400).SendString(err.Error())
		}
		got = u.String()
		return nil
	})
	req := httptest.NewRequest("GET", target, nil)
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		return "ERR"
	}
	return got
}

func TestResolveOriginal(t *testing.T) {
	cases := []struct {
		name    string
		trusted bool
		host    string
		target  string
		hdr     map[string]string
		want    string
	}{
		{"ingress-nginx", true, "id.example.com", "/forward-auth/verify", map[string]string{"X-Original-URL": "https://kubecost.example.com/a?b=1"}, "https://kubecost.example.com/a?b=1"},
		{"traefik", true, "id.example.com", "/forward-auth/verify", map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "Kubecost.example.com", "X-Forwarded-Uri": "/a?b=1"}, "https://kubecost.example.com/a?b=1"},
		{"envoy prefix", false, "kubecost.example.com", "/forward-auth/verify/a/b?c=2", nil, "https://kubecost.example.com/a/b?c=2"},
		{"envoy prefix root", false, "kubecost.example.com", "/forward-auth/verify", nil, "https://kubecost.example.com/"},
		{"cilium", true, "kubecost.example.com", "/a", nil, "https://kubecost.example.com/a"},
		{"untrusted forwarded headers", false, "evil.example.org", "/forward-auth/verify", map[string]string{"X-Original-URL": "https://kubecost.example.com/", "X-Forwarded-Host": "kubecost.example.com", "X-Forwarded-Proto": "https"}, "https://evil.example.org/"},
		{"bad original", true, "id.example.com", "/x", map[string]string{"X-Original-URL": "/relative"}, "ERR"},
		{"bad proto", true, "id.example.com", "/x", map[string]string{"X-Forwarded-Proto": "javascript", "X-Forwarded-Host": "a.example.com"}, "ERR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveVia(t, tc.trusted, tc.host, tc.target, tc.hdr); got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func TestValidRedirect(t *testing.T) {
	const host = "kubecost.example.com"
	for _, raw := range []string{
		"https://app.example.com@evil.org/",
		"https://kubecost.example.com@evil.org/",
		"https://kubecost.example.com:pw@kubecost.example.com/",
		"//evil.org",
		`https:/\evil.org`,
		`https://kubecost.example.com\@evil.org/`,
		"https://APP.example.com.evil.org",
		"https://kubecost.example.com.evil.org/",
		"https://evil.org/%2F%2Fkubecost.example.com",
		"http://kubecost.example.com/",
		"/path",
		"",
		"https://kubecost.example.com/a\nb",
		"https://kubecost.example.com/a\x00",
		"https://kubecost.example.com:8443/",
		"javascript:alert(1)",
	} {
		if u, ok := validRedirect(raw, host); ok {
			t.Errorf("%q accepted as %v", raw, u)
		}
	}
	u, ok := validRedirect("https://kubecost.example.com/x?y=1", host)
	if !ok || u.String() != "https://kubecost.example.com/x?y=1" {
		t.Fatalf("valid rejected: %v %v", u, ok)
	}
	if _, ok := validRedirect("https://KubeCost.Example.com/x", host); !ok {
		t.Fatal("case-insensitive host rejected")
	}
	if _, ok := validRedirect("https://kubecost.example.com/%2F%2Fevil", host); !ok {
		t.Fatal("encoded path on the right host is fine")
	}
}
