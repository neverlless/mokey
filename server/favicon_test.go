package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// #26: site.favicon was ignored because the page linked straight at the
// embedded /static asset instead of the path the favicon route serves
func TestCustomFaviconIsServed(t *testing.T) {
	assert := assert.New(t)

	custom := filepath.Join(t.TempDir(), "custom.png")
	if err := os.WriteFile(custom, []byte("\x89PNG\r\n\x1a\nfake"), 0o600); err != nil {
		t.Fatalf("write favicon: %s", err)
	}

	app, _, _ := newTestAppWith(t, func() {
		viper.Set("site.favicon", custom)
	})

	tc := newTestClient(t, app)

	// the page must point at the route the favicon is served from
	body := readBody(t, tc.get("/auth/login"))
	assert.Contains(body, `href="/favicon.ico"`)
	assert.NotContains(body, "/static/images/favicon.ico")

	resp := tc.get("/favicon.ico")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("\x89PNG\r\n\x1a\nfake", readBody(t, resp))
	// a .png must not be announced as image/x-icon
	assert.Contains(resp.Header.Get("Content-Type"), "image/png")
}

// the built-in icon must still be served when nothing is configured
func TestDefaultFaviconIsServed(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)

	resp := newTestClient(t, app).get("/favicon.ico")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.NotEmpty(readBody(t, resp))
}
