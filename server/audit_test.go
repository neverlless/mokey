package server

import (
	"io"
	"testing"

	"github.com/gofiber/storage/memory/v2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestAuditHookAndRecent(t *testing.T) {
	assert := assert.New(t)
	storage := memory.New()
	hook := NewAuditHook(storage)

	logger := log.New()
	logger.AddHook(hook)
	logger.SetLevel(log.InfoLevel)
	logger.SetOutput(io.Discard)

	logger.WithFields(log.Fields{"username": "jdoe", "ip": "1.2.3.4"}).Info("AUDIT user logged in")
	logger.WithFields(log.Fields{"username": "jdoe", "admin": "root", "ip": "1.2.3.4"}).Info("AUDIT admin user action")
	logger.Info("not an audit line")

	events := auditRecent(storage, 10)
	assert.Len(events, 2)
	// newest first
	assert.Equal("admin user action", events[0].Message)
	assert.Equal("root", events[0].Actor)
	assert.Equal("user logged in", events[1].Message)
	assert.Equal("jdoe", events[1].Username)
	assert.Equal("1.2.3.4", events[1].IP)
}
