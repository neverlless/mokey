package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/storage/memory/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type hookRecorder struct {
	mu    sync.Mutex
	fails int // answer this many requests with 500 first
	reqs  []*http.Request
	body  [][]byte
}

func (h *hookRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reqs = append(h.reqs, r)
	h.body = append(h.body, b)
	if h.fails > 0 {
		h.fails--
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (h *hookRecorder) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.reqs)
}

func (h *hookRecorder) serve(t *testing.T) string {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// a value logged under a secret key that must never come back out
const redactProbe = "probe-7f3a"

func TestWebhookDelivery(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	orig := webhookBackoff
	webhookBackoff = time.Millisecond
	t.Cleanup(func() { webhookBackoff = orig })

	signed := &hookRecorder{fails: 2}
	logins := &hookRecorder{}
	slack := &hookRecorder{}

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("webhooks", []map[string]any{
		{"url": signed.serve(t), "secret": "shared-key"},
		{"url": logins.serve(t), "events": []string{"LOGGED IN"}},
		{"url": slack.serve(t), "format": "slack", "events": []string{"password"}},
	})
	hooks, err := newWebhooks()
	require.NoError(err)

	h := NewAuditHandler(slog.NewTextHandler(io.Discard, nil), memory.New())
	h.hooks = hooks
	logger := slog.New(h)

	logger.Info("AUDIT User password changed", "username", "jdoe", "ip", "1.2.3.4", "password", redactProbe)
	logger.Info("not an audit line")
	logger.Info("AUDIT User logged in", "username", "jdoe")

	require.Eventually(func() bool {
		return signed.count() == 4 && logins.count() == 1 && slack.count() == 1
	}, 5*time.Second, 10*time.Millisecond)

	// two 500s, then the first event delivered on the third try
	var event AuditEvent
	require.NoError(json.Unmarshal(signed.body[2], &event))
	assert.Equal(int64(1), event.Seq)
	assert.Equal("User password changed", event.Message)
	assert.Equal("jdoe", event.Username)
	assert.Equal("1.2.3.4", event.IP)
	assert.Equal(redacted, event.Attrs["password"])
	assert.NotContains(string(signed.body[2]), redactProbe)

	r := signed.reqs[2]
	ts := r.Header.Get("X-Mokey-Timestamp")
	assert.NotEmpty(ts)
	assert.Equal("sha256="+webhookSignature("shared-key", ts, signed.body[2]), r.Header.Get("X-Mokey-Signature"))
	assert.NotEqual("sha256="+webhookSignature("other-key", ts, signed.body[2]), r.Header.Get("X-Mokey-Signature"))

	// unsigned without a secret, and the filter only let the login through
	assert.Empty(logins.reqs[0].Header.Get("X-Mokey-Signature"))
	assert.Contains(string(logins.body[0]), "User logged in")

	assert.JSONEq(`{"text":"mokey: User password changed user=jdoe ip=1.2.3.4"}`, string(slack.body[0]))
}

func TestWebhookConfigRejected(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("webhooks", []map[string]any{{"url": "ftp://example.com"}})
	_, err := newWebhooks()
	assert.Error(t, err)

	viper.Set("webhooks", []map[string]any{{"url": "https://example.com", "format": "teams"}})
	_, err = newWebhooks()
	assert.Error(t, err)
}
