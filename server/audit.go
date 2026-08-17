// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

// The audit store is a ring buffer of the last auditRingSize AUDIT log
// events, kept in the existing session storage backend (memory, sqlite3,
// or redis) — no separate schema. Events are captured by a logrus hook, so
// every existing and future log line starting with "AUDIT" lands here
// without touching call sites.
// ponytail: the ring counter is not atomic — fine for a single mokey
// instance; move to a proper store if multi-instance audit is ever needed.
const (
	auditRingSize  = 1000
	auditSeqKey    = "audit-seq"
	auditEntryKey  = "audit-entry-"
	auditRetention = 90 * 24 * time.Hour
)

type AuditEvent struct {
	Time     time.Time `json:"time"`
	Message  string    `json:"message"`
	Username string    `json:"username,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	IP       string    `json:"ip,omitempty"`
}

type AuditHook struct {
	storage fiber.Storage
}

func NewAuditHook(storage fiber.Storage) *AuditHook {
	return &AuditHook{storage: storage}
}

func (h *AuditHook) Levels() []log.Level {
	// ErrorLevel included: failed logins are logged as AUDIT errors and
	// belong in the trail
	return []log.Level{log.InfoLevel, log.WarnLevel, log.ErrorLevel}
}

func (h *AuditHook) Fire(entry *log.Entry) error {
	if !strings.HasPrefix(entry.Message, "AUDIT") {
		return nil
	}

	event := AuditEvent{
		Time:    entry.Time,
		Message: strings.TrimSpace(strings.TrimPrefix(entry.Message, "AUDIT")),
	}
	if v, ok := entry.Data["username"].(string); ok {
		event.Username = v
	}
	if v, ok := entry.Data["admin"].(string); ok {
		event.Actor = v
	}
	if v, ok := entry.Data["invited_by"].(string); ok {
		event.Actor = v
	}
	if v, ok := entry.Data["ip"].(string); ok {
		event.IP = v
	}
	if event.Username == "" {
		if v, ok := entry.Data["email"].(string); ok {
			event.Username = v
		}
	}

	b, err := json.Marshal(event)
	if err != nil {
		return nil
	}

	seq := int64(0)
	if raw, _ := h.storage.Get(auditSeqKey); raw != nil {
		seq, _ = strconv.ParseInt(string(raw), 10, 64)
	}
	seq++

	h.storage.Set(fmt.Sprintf("%s%d", auditEntryKey, seq%auditRingSize), b, auditRetention)
	h.storage.Set(auditSeqKey, []byte(strconv.FormatInt(seq, 10)), 0)

	return nil
}

// auditRecent returns up to n most recent audit events, newest first.
func auditRecent(storage fiber.Storage, n int) []AuditEvent {
	seq := int64(0)
	if raw, _ := storage.Get(auditSeqKey); raw != nil {
		seq, _ = strconv.ParseInt(string(raw), 10, 64)
	}

	events := make([]AuditEvent, 0, n)
	for i := seq; i > 0 && i > seq-int64(auditRingSize) && len(events) < n; i-- {
		raw, _ := storage.Get(fmt.Sprintf("%s%d", auditEntryKey, i%auditRingSize))
		if raw == nil {
			continue
		}
		var e AuditEvent
		if json.Unmarshal(raw, &e) == nil {
			events = append(events, e)
		}
	}

	return events
}

// auditUserRecent returns up to n most recent audit events involving the
// given user (as subject or actor), newest first. Scans the whole ring.
func auditUserRecent(storage fiber.Storage, username string, n int) []AuditEvent {
	seq := int64(0)
	if raw, _ := storage.Get(auditSeqKey); raw != nil {
		seq, _ = strconv.ParseInt(string(raw), 10, 64)
	}

	events := make([]AuditEvent, 0, n)
	for i := seq; i > 0 && i > seq-int64(auditRingSize) && len(events) < n; i-- {
		raw, _ := storage.Get(fmt.Sprintf("%s%d", auditEntryKey, i%auditRingSize))
		if raw == nil {
			continue
		}
		var e AuditEvent
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		if e.Username == username || e.Actor == username {
			events = append(events, e)
		}
	}

	return events
}
