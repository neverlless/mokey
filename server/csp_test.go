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
	viper.Set("server.csp", map[string]any{"img-src": []string{"data:", "blob:", "https:"}})
	_, err = loadCSPExtra()
	assert.NoError(t, err, "scheme sources are fine outside script-src")
}

func TestCSPExtraOnForwardAuthPage(t *testing.T) {
	app, _, _ := newFAApp(t, func() {
		viper.Set("server.csp", map[string]any{"font-src": []string{"https://fonts.example.org"}})
	})
	csp := newTestClient(t, app).verify(traefik).Header.Get("Content-Security-Policy")
	assert.Contains(t, csp, "font-src 'self' https://"+faMokeyHost+" https://fonts.example.org")
}
