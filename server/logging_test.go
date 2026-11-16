package server

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestRedactAttr(t *testing.T) {
	tests := []struct {
		attr slog.Attr
		want string
	}{
		{slog.String("password", "hunter2"), redacted},
		{slog.String("Password", "hunter2"), redacted},
		{slog.String("new_password", "hunter2"), redacted},
		{slog.String("smtp_password", "hunter2"), redacted},
		{slog.String("otp", "123456"), redacted},
		{slog.String("token", "abc"), redacted},
		{slog.String("client_secret", "abc"), redacted},
		{slog.String("csrf_secret", "abc"), redacted},
		{slog.Int("token", 42), redacted},
		{slog.String("username", "walter"), "walter"},
		{slog.String("token_type", "reset-"), "reset-"},
		{slog.String("url", "redis://mokey:s3cret@redis:6379/0"), "redis://mokey:" + redacted + "@redis:6379/0"},
		{slog.String("url", "redis://:s3cret@redis:6379/0"), "redis://:" + redacted + "@redis:6379/0"},
		{slog.String("url", "redis://mokey@redis:6379/0"), "redis://mokey@redis:6379/0"},
		{slog.String("url", "https://hydra:4445/admin"), "https://hydra:4445/admin"},
		{slog.Any("err", errors.New(`parse "redis://u:s3cret@host:bad/0": invalid port`)), `parse "redis://u:` + redacted + `@host:bad/0": invalid port`},
		{slog.Any("err", errors.New("plain failure")), "plain failure"},
		{slog.String("msg", "dial rediss://u:pw@h:1 failed"), "dial rediss://u:" + redacted + "@h:1 failed"},
	}
	for _, tt := range tests {
		got := redactAttr(nil, tt.attr)
		assert.Equal(t, tt.attr.Key, got.Key)
		assert.Equal(t, tt.want, got.Value.String(), "%s=%v", tt.attr.Key, tt.attr.Value)
	}
}

func TestLogHandlerRedacts(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(&buf))
	logger.Error("connect to redis://u:s3cret@h:6379 failed", "password", "hunter2", "err", fmt.Errorf("wrapped: %w", errors.New("redis://u:s3cret@h:6379")))
	out := buf.String()
	assert.NotContains(t, out, "s3cret")
	assert.NotContains(t, out, "hunter2")
	assert.Contains(t, out, "level=ERROR")
}

func TestRedactURL(t *testing.T) {
	assert.Equal(t, "redis://mokey:xxxxx@redis:6379/0", redactURL("redis://mokey:s3cret@redis:6379/0"))
	assert.Equal(t, "redis://redis:6379/0", redactURL("redis://redis:6379/0"))
	assert.Equal(t, "redis://u:"+redacted+"@host:bad/0", redactURL("redis://u:s3cret@host:bad/0"))
}

func TestNewStorageErrorRedactsRedisPassword(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Set("storage.driver", "redis")
	viper.Set("storage.redis.url", "redis://u:s3cret@host:badport/0")

	_, err := newStorage()
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cret")
	assert.True(t, strings.Contains(err.Error(), "host:badport"), err.Error())
}

// A status without its own error page (a client that stalls past
// server.read_timeout gets 408) is answered without a template error.
func TestErrorHandlerStatusWithoutTemplate(t *testing.T) {
	engine, err := NewTemplateRenderer()
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{ErrorHandler: HTTPErrorHandler, Views: engine, PassLocalsToViews: true})
	app.Get("/zz-timeout", func(c fiber.Ctx) error { return fiber.ErrRequestTimeout })

	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(saved) })

	resp, err := app.Test(httptest.NewRequest("GET", "/zz-timeout", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusRequestTimeout {
		t.Fatalf("status %d, want 408", resp.StatusCode)
	}
	out := logs.String()
	if strings.Contains(out, "Failed to render") || strings.Contains(out, "<nil>") || strings.Contains(out, "level=ERROR") {
		t.Fatalf("unexpected log: %s", out)
	}
}

func TestSlackTime(t *testing.T) {
	assert.Equal(t, "2026-11-16T17:43:36.779Z", slackTime("1794851016.779229"))
	assert.Equal(t, "not-a-ts", slackTime("not-a-ts"))
}
