// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

// The audit store is a ring buffer of the last auditRingSize AUDIT log
// events, kept in the existing session storage backend (memory, sqlite3,
// or redis) — no separate schema. Events are captured by a slog handler, so
// every existing and future log line starting with "AUDIT" lands here
// without touching call sites.
const (
	auditRingSize  = 1000
	auditSeqKey    = "audit-seq"
	auditEntryKey  = "audit-entry-"
	auditRetention = 90 * 24 * time.Hour
)

type AuditEvent struct {
	Seq      int64             `json:"seq"`
	Time     time.Time         `json:"time"`
	Level    string            `json:"level,omitempty"`
	Message  string            `json:"message"`
	Username string            `json:"username,omitempty"`
	Actor    string            `json:"actor,omitempty"`
	IP       string            `json:"ip,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

// AuditHandler wraps the default slog handler and copies every AUDIT record
// into the ring buffer before passing it on.
type AuditHandler struct {
	slog.Handler
	storage fiber.Storage
	lock    *storeLock
	hooks   *webhooks
	attrs   []slog.Attr
}

func NewAuditHandler(next slog.Handler, storage fiber.Storage) *AuditHandler {
	// re-wrapping on every NewRouter (tests build many) must not stack hooks
	if h, ok := next.(*AuditHandler); ok {
		next = h.Handler
	}
	return &AuditHandler{Handler: next, storage: storage, lock: newStoreLock(storage)}
}

func (h *AuditHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.Handler = h.Handler.WithAttrs(attrs)
	c.attrs = append(slices.Clip(h.attrs), attrs...)
	return &c
}

func (h *AuditHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.Handler = h.Handler.WithGroup(name)
	return &c
}

func (h *AuditHandler) Handle(ctx context.Context, r slog.Record) error {
	// Info and above: failed logins are logged as AUDIT errors and belong in
	// the trail
	if r.Level >= slog.LevelInfo && strings.HasPrefix(r.Message, "AUDIT") {
		event, err := h.record(r)
		if err != nil {
			slog.Error("Failed to store audit event", "err", err)
		}
		h.hooks.send(event)
	}
	return h.Handler.Handle(ctx, r)
}

// record stores the event and returns it; attrs leave here already
// redacted, as they also go to the API and webhooks.
func (h *AuditHandler) record(r slog.Record) (AuditEvent, error) {
	data := map[string]string{}
	add := func(a slog.Attr) bool {
		a = redactAttr(nil, a)
		if v := a.Value.Resolve(); v.Kind() != slog.KindGroup {
			data[a.Key] = v.String()
		}
		return true
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(add)

	event := AuditEvent{
		Time:     r.Time,
		Level:    r.Level.String(),
		Message:  redactURLs(strings.TrimSpace(strings.TrimPrefix(r.Message, "AUDIT"))),
		Username: data["username"],
		Actor:    data["admin"],
		IP:       data["ip"],
		Attrs:    data,
	}
	if v := data["invited_by"]; v != "" {
		event.Actor = v
	}
	if event.Username == "" {
		event.Username = data["email"]
	}

	seq, err := h.lock.incr(auditSeqKey)
	if err != nil {
		return event, err
	}
	event.Seq = seq

	b, err := json.Marshal(event)
	if err != nil {
		return event, nil
	}
	return event, h.storage.Set(fmt.Sprintf("%s%d", auditEntryKey, seq%auditRingSize), b, auditRetention)
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

// auditAfter returns up to n events with seq > after, oldest first. Events
// that dropped out of the ring are skipped. A cursor ahead of the counter
// (memory storage restarted) starts over from the oldest event.
func auditAfter(storage fiber.Storage, after int64, n int) []AuditEvent {
	seq := int64(0)
	if raw, _ := storage.Get(auditSeqKey); raw != nil {
		seq, _ = strconv.ParseInt(string(raw), 10, 64)
	}
	if after > seq || after < 0 {
		after = 0
	}

	events := make([]AuditEvent, 0, n)
	for i := max(after, seq-auditRingSize) + 1; i <= seq && len(events) < n; i++ {
		raw, _ := storage.Get(fmt.Sprintf("%s%d", auditEntryKey, i%auditRingSize))
		if raw == nil {
			continue
		}
		var e AuditEvent
		if json.Unmarshal(raw, &e) != nil {
			continue
		}
		// entries written before v2.8 carry no seq
		if e.Seq == 0 {
			e.Seq = i
		}
		if e.Seq == i {
			events = append(events, e)
		}
	}

	return events
}
