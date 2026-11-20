package server

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCSPExtraSources(t *testing.T) {
	app, _, _ := newTestAppWith(t, func() {
		viper.Set("server.csp", map[string]any{
			"font-src": []string{"https://fonts.example.org"},
			"img-src":  []string{"https://cdn.example.org"},
		})
	})
	csp := newTestClient(t, app).get("/auth/login").Header.Get("Content-Security-Policy")
	assert.Contains(t, csp, "img-src 'self' data: https://cdn.example.org;")
	assert.Contains(t, csp, "font-src 'self' https://fonts.example.org")
	assert.Contains(t, csp, "default-src 'self';")
	assert.Contains(t, csp, "script-src 'self' 'nonce-")
}

func TestCSPBaseUnchangedWithoutExtras(t *testing.T) {
	viper.Reset()
	x, err := loadCSPExtra()
	require.NoError(t, err)
	assert.Equal(t, "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-N'",
		contentSecurityPolicy("N", "", x))
	assert.Equal(t, "default-src 'self'; img-src 'self' data: https://o; style-src 'self' 'unsafe-inline' https://o; font-src 'self' https://o; script-src 'self' 'nonce-N'",
		contentSecurityPolicy("N", "https://o", x))
}

func TestCSPExtraAppendsToExistingAndNewDirectives(t *testing.T) {
	viper.Reset()
	viper.Set("server.csp", map[string]any{
		"script-src":  []string{"https://js.example.org"},
		"connect-src": []string{"https://api.example.org", "wss://ws.example.org"},
		"font-src":    []string{"https://fonts.example.org"},
	})
	x, err := loadCSPExtra()
	require.NoError(t, err)
	assert.Equal(t, "default-src 'self'; img-src 'self' data: https://o; style-src 'self' 'unsafe-inline' https://o; font-src 'self' https://o https://fonts.example.org; script-src 'self' 'nonce-N' https://js.example.org; connect-src 'self' https://api.example.org wss://ws.example.org",
		contentSecurityPolicy("N", "https://o", x))
}

func TestCSPExtraRejected(t *testing.T) {
	for name, cfg := range map[string]map[string]any{
		"unknown directive": {"form-action": []string{"https://x.example.org"}},
		"empty source":      {"img-src": []string{""}},
		"semicolon":         {"img-src": []string{"https://x.example.org;script-src"}},
		"comma":             {"img-src": []string{"https://a.example.org,https://b.example.org"}},
		"whitespace":        {"img-src": []string{"https://a.example.org https://b.example.org"}},
		"script inline":     {"script-src": []string{"'unsafe-inline'"}},
		"script eval":       {"script-src": []string{"'UNSAFE-EVAL'"}},
		"script hashes":     {"script-src": []string{"'unsafe-hashes'"}},
		"script star":       {"script-src": []string{"*"}},
		"script data":       {"script-src": []string{"data:"}},
		"script blob":       {"script-src": []string{"blob:"}},
		"script https":      {"script-src": []string{"https:"}},
		"script http":       {"script-src": []string{"http:"}},
		"script any host":   {"script-src": []string{"https://*"}},
		"default inline":    {"default-src": []string{"'unsafe-inline'"}},
		"default data":      {"default-src": []string{"data:"}},
		"strict-dynamic":    {"script-src": []string{"'strict-dynamic'"}},
		"default strict":    {"default-src": []string{"'Strict-Dynamic'"}},
		"wasm eval":         {"script-src": []string{"'wasm-unsafe-eval'"}},
		"allow redirects":   {"script-src": []string{"'unsafe-allow-redirects'"}},
		"speculation":       {"default-src": []string{"'inline-speculation-rules'"}},
		"any host port":     {"script-src": []string{"https://*:443"}},
		"any host any port": {"script-src": []string{"https://*:*"}},
		"bare any port":     {"script-src": []string{"*:443"}},
		"any host slash":    {"script-src": []string{"https://*/"}},
		"tld wildcard":      {"script-src": []string{"https://*.com"}},
		"bare tld wildcard": {"default-src": []string{"*.org"}},
		"none":              {"img-src": []string{"'none'"}},
		"control char":      {"img-src": []string{"https://x.example.org\x00"}},
		"del char":          {"img-src": []string{"https://x.example.org\x7f"}},
		"value not list":    {"img-src": 42},
		"item not string":   {"img-src": []any{"https://x.example.org", 7}},
	} {
		viper.Reset()
		viper.Set("server.csp", cfg)
		_, err := loadCSPExtra()
		assert.ErrorContains(t, err, "server.csp", name)
	}

	viper.Reset()
	viper.Set("server.csp", map[string]any{"frame-ancestors": []string{"'none'"}})
	_, err := loadCSPExtra()
	assert.ErrorContains(t, err, "frame-ancestors")

	viper.Reset()
	viper.Set("server.csp", "font-src=https://x.example.org")
	_, err = loadCSPExtra()
	assert.ErrorContains(t, err, "server.csp", "not a table")

	viper.Reset()
	viper.Set("server.csp", map[string]any{"img-src": []any{"data:", "blob:", "https:"}})
	_, err = loadCSPExtra()
	assert.NoError(t, err, "scheme sources are fine outside script-src")

	viper.Reset()
	viper.Set("server.csp", map[string]any{"script-src": []string{"https://*.cdn.example.org", "https://js.example.org:8443/lib/"}})
	_, err = loadCSPExtra()
	assert.NoError(t, err, "subdomain wildcards and ports are fine")
}

func TestCSPDefaultSrcExtras(t *testing.T) {
	viper.Reset()
	viper.Set("server.csp", map[string]any{
		"default-src": []string{"https://all.example.org"},
		"font-src":    []string{"https://fonts.example.org"},
	})
	x, err := loadCSPExtra()
	require.NoError(t, err)
	assert.Equal(t, "default-src 'self' https://all.example.org; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' https://all.example.org https://fonts.example.org; script-src 'self' 'nonce-N'",
		contentSecurityPolicy("N", "", x))
	assert.Equal(t, "default-src 'self' https://all.example.org; img-src 'self' data: https://o; style-src 'self' 'unsafe-inline' https://o; font-src 'self' https://all.example.org https://o https://fonts.example.org; script-src 'self' 'nonce-N'",
		contentSecurityPolicy("N", "https://o", x))
}

func TestCSPExtraOnForwardAuthPage(t *testing.T) {
	app, _, _ := newFAApp(t, func() {
		viper.Set("server.csp", map[string]any{"font-src": []string{"https://fonts.example.org"}})
	})
	csp := newTestClient(t, app).verify(traefik).Header.Get("Content-Security-Policy")
	assert.Contains(t, csp, "font-src 'self' https://"+faMokeyHost+" https://fonts.example.org")
}
