package server

import (
	"io"
	"log/slog"
	"testing"

	"github.com/gofiber/storage/memory/v2"
	"github.com/stretchr/testify/assert"
)

func TestAuditHookAndRecent(t *testing.T) {
	assert := assert.New(t)
	storage := memory.New()
	logger := slog.New(NewAuditHandler(slog.NewTextHandler(io.Discard, nil), storage))

	logger.Info("AUDIT user logged in", "username", "jdoe", "ip", "1.2.3.4")
	logger.With("ip", "1.2.3.4").Info("AUDIT admin user action", "username", "jdoe", "admin", "root")
	logger.Info("not an audit line")
	logger.Debug("AUDIT below info is not kept")

	events := auditRecent(storage, 10)
	assert.Len(events, 2)
	// newest first
	assert.Equal("admin user action", events[0].Message)
	assert.Equal("root", events[0].Actor)
	assert.Equal("1.2.3.4", events[0].IP)
	assert.Equal("user logged in", events[1].Message)
	assert.Equal("jdoe", events[1].Username)
	assert.Equal("1.2.3.4", events[1].IP)
}
