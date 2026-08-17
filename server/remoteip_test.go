package server

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// echoIP spins a bare fiber app that echoes RemoteIP for the request.
// app.Test connections always have peer address 0.0.0.0.
func echoIP(t *testing.T, xff string) string {
	t.Helper()
	app := fiber.New()
	app.Get("/ip", func(c *fiber.Ctx) error {
		return c.SendString(RemoteIP(c))
	})

	req := httptest.NewRequest("GET", "/ip", nil)
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	return readBody(t, resp)
}

func TestRemoteIPIgnoresXFFWithoutTrustedProxy(t *testing.T) {
	assert := assert.New(t)
	viper.Reset()

	assert.Equal("0.0.0.0", echoIP(t, ""))
	// client-supplied X-Forwarded-For must not be believed
	assert.Equal("0.0.0.0", echoIP(t, "1.2.3.4"))
}

func TestRemoteIPBehindTrustedProxy(t *testing.T) {
	assert := assert.New(t)
	viper.Reset()
	viper.Set("server.trusted_proxies", []string{"0.0.0.0", "10.0.0.0/8"})

	// rightmost non-trusted entry wins; leftmost entries are forgeable
	assert.Equal("203.0.113.9", echoIP(t, "6.6.6.6, 203.0.113.9"))
	// trusted hops on the right are skipped
	assert.Equal("203.0.113.9", echoIP(t, "6.6.6.6, 203.0.113.9, 10.1.2.3"))
	// everything trusted (or garbage) falls back to the peer address
	assert.Equal("0.0.0.0", echoIP(t, "10.1.2.3"))
	assert.Equal("0.0.0.0", echoIP(t, "not-an-ip"))
	assert.Equal("0.0.0.0", echoIP(t, ""))
}
