package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunSyncRefusesNonRedis(t *testing.T) {
	viper.Set("storage.driver", "memory")
	t.Cleanup(func() { viper.Set("storage.driver", "memory") })
	var out bytes.Buffer
	code, err := RunSync(context.Background(), false, &out)
	assert.Equal(t, 1, code)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sync.interval")
}

func TestRunSyncDisabled(t *testing.T) {
	r, _, _, _ := syncRunRouter(t)
	r.sync = nil
	code, err := r.runSync(context.Background(), false, &bytes.Buffer{})
	assert.Equal(t, 1, code)
	assert.Error(t, err)
}

func TestRunSyncExitCodes(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		r, fake, src, _ := syncRunRouter(t)
		managed(fake, "jesse")
		src.users = []syncSourceUser{googleUser("jesse")}
		var out bytes.Buffer
		code, err := r.runSync(context.Background(), true, &out)
		require.NoError(t, err)
		assert.Equal(t, 0, code)
		assert.Contains(t, out.String(), "dry run")
	})
	t.Run("source error", func(t *testing.T) {
		r, _, src, _ := syncRunRouter(t)
		src.err = errors.New("google down")
		var out bytes.Buffer
		code, err := r.runSync(context.Background(), false, &out)
		assert.Error(t, err)
		assert.Equal(t, 1, code)
		assert.Contains(t, out.String(), "google down")
	})
	t.Run("brake", func(t *testing.T) {
		r, _ := brakeSetup(t)
		var out bytes.Buffer
		code, err := r.runSync(context.Background(), false, &out)
		require.NoError(t, err)
		assert.Equal(t, 2, code)
		assert.Contains(t, out.String(), "held by the brake")
	})
	t.Run("claim held", func(t *testing.T) {
		r, _, _, _ := syncRunRouter(t)
		_, ok, err := r.lock.claim(syncRunKey, syncRunTTL)
		require.NoError(t, err)
		require.True(t, ok)
		code, err := r.runSync(context.Background(), false, &bytes.Buffer{})
		assert.Equal(t, 1, code)
		assert.Error(t, err)
	})
}

func TestRunSyncFlushesWebhooks(t *testing.T) {
	r, fake, src, _ := syncRunRouter(t)
	managed(fake, "jesse")
	src.users = []syncSourceUser{googleUser("jesse")}

	got := &hookRecorder{}
	viper.Set("webhooks", []map[string]any{{"url": got.serve(t)}})
	t.Cleanup(func() { viper.Set("webhooks", nil) })
	hooks, err := newWebhooks()
	require.NoError(t, err)
	r.hooks = hooks
	h := NewAuditHandler(slog.Default().Handler(), r.storage)
	h.hooks = hooks
	slog.SetDefault(slog.New(h))

	code, err := r.runSync(context.Background(), false, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Equal(t, 0, code)
	// no waiting: `mokey sync` exits right after runSync
	got.mu.Lock()
	defer got.mu.Unlock()
	require.NotEmpty(t, got.body)
	assert.True(t, strings.Contains(string(got.body[len(got.body)-1]), "sync run"))
}
