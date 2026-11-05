// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	webhookQueueSize = 100
	webhookAttempts  = 3
	webhookTimeout   = 5 * time.Second
)

// a var so tests don't sleep through real backoff
var webhookBackoff = time.Second

type webhookConfig struct {
	URL    string   `mapstructure:"url"`
	Secret string   `mapstructure:"secret"`
	Events []string `mapstructure:"events"`
	Format string   `mapstructure:"format"`
}

type webhookTarget struct {
	webhookConfig
	queue chan AuditEvent
}

// webhooks posts audit events to the [[webhooks]] targets. Each target has
// its own bounded queue and worker, so a dead endpoint only drops its own
// events and never blocks the request that logged them.
type webhooks struct {
	targets []*webhookTarget
	client  *http.Client
}

func newWebhooks() (*webhooks, error) {
	var cfgs []webhookConfig
	if err := viper.UnmarshalKey("webhooks", &cfgs); err != nil {
		return nil, fmt.Errorf("webhooks: %w", err)
	}
	if len(cfgs) == 0 {
		return nil, nil
	}

	w := &webhooks{client: &http.Client{Timeout: webhookTimeout}}
	for i, cfg := range cfgs {
		if !strings.HasPrefix(cfg.URL, "https://") && !strings.HasPrefix(cfg.URL, "http://") {
			return nil, fmt.Errorf("webhooks[%d].url must be an http(s) URL", i)
		}
		if cfg.Format != "" && cfg.Format != "slack" {
			return nil, fmt.Errorf("webhooks[%d].format must be empty or \"slack\"", i)
		}
		t := &webhookTarget{webhookConfig: cfg, queue: make(chan AuditEvent, webhookQueueSize)}
		w.targets = append(w.targets, t)
		go w.run(t)
	}
	return w, nil
}

func (t *webhookTarget) wants(message string) bool {
	if len(t.Events) == 0 {
		return true
	}
	m := strings.ToLower(message)
	for _, e := range t.Events {
		if strings.Contains(m, strings.ToLower(e)) {
			return true
		}
	}
	return false
}

func (w *webhooks) send(event AuditEvent) {
	if w == nil {
		return
	}
	for _, t := range w.targets {
		if !t.wants(event.Message) {
			continue
		}
		select {
		case t.queue <- event:
		default:
			slog.Warn("Webhook queue full, dropping event",
				"url", redactURL(t.URL),
				"seq", event.Seq,
			)
		}
	}
}

func (w *webhooks) run(t *webhookTarget) {
	for event := range t.queue {
		body, err := t.body(event)
		if err != nil {
			continue
		}
		for attempt := 1; ; attempt++ {
			err = w.post(t, body)
			if err == nil {
				break
			}
			if attempt == webhookAttempts {
				slog.Error("Webhook delivery failed",
					"url", redactURL(t.URL),
					"seq", event.Seq,
					"err", err,
				)
				break
			}
			time.Sleep(webhookBackoff * time.Duration(attempt))
		}
	}
}

func (t *webhookTarget) body(event AuditEvent) ([]byte, error) {
	if t.Format != "slack" {
		return json.Marshal(event)
	}

	text := "mokey: " + event.Message
	for _, kv := range [][2]string{{"user", event.Username}, {"by", event.Actor}, {"ip", event.IP}} {
		if kv[1] != "" {
			text += " " + kv[0] + "=" + kv[1]
		}
	}
	return json.Marshal(map[string]string{"text": text})
}

func (w *webhooks) post(t *webhookTarget, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mokey-webhook")
	if t.Secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("X-Mokey-Timestamp", ts)
		req.Header.Set("X-Mokey-Signature", "sha256="+webhookSignature(t.Secret, ts, body))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// webhookSignature is HMAC-SHA256 over "<timestamp>.<body>"; the timestamp
// is signed so a captured request can't be replayed later as fresh.
func webhookSignature(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
