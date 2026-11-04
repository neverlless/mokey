package server

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
)

// HEAD must reach the GET route itself, not the catch-all 404, and health
// probes must not create sessions
func TestHeadFollowsGetRoute(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)
	tc := newTestClient(t, app)

	resp := tc.do(httptest.NewRequest(fiber.MethodHead, "/healthz", nil))
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Empty(resp.Header.Get("Set-Cookie"))

	resp = tc.do(httptest.NewRequest(fiber.MethodHead, "/auth/login", nil))
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}

func TestStaticAssets(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)
	tc := newTestClient(t, app)

	resp := tc.get("/static/css/style.css")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("public, max-age=900", resp.Header.Get("Cache-Control"))
	assert.Empty(resp.Header.Get("Last-Modified"))

	for _, path := range []string{"/static", "/static/", "/static/css", "/static/css/"} {
		resp := tc.get(path)
		assert.Equal(fiber.StatusNotFound, resp.StatusCode, path)
		assert.NotEmpty(resp.Header.Get("Content-Security-Policy"), path)
		assert.Equal("DENY", resp.Header.Get("X-Frame-Options"), path)
	}
}
