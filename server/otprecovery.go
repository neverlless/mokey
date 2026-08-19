// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"encoding/json"
	"time"
)

// OTP recovery request queue: single storage key holding a JSON list,
// same durability as the session index (memory/sqlite3/redis).
// ponytail: no cross-instance lock — a concurrent removal loses at worst
// a redundant queue write; OTP recovery itself is idempotent.

const (
	otpRecoveryKey = "otprecovery"
	otpRecoveryTTL = 30 * 24 * time.Hour
)

type OTPRecoveryRequest struct {
	Username    string    `json:"username"`
	RequestedAt time.Time `json:"requested_at"`
}

func (r *Router) loadOTPRecoveryRequests() []OTPRecoveryRequest {
	raw, err := r.storage.Get(otpRecoveryKey)
	if err != nil || raw == nil {
		return nil
	}
	var reqs []OTPRecoveryRequest
	if err := json.Unmarshal(raw, &reqs); err != nil {
		return nil
	}
	return reqs
}

func (r *Router) saveOTPRecoveryRequests(reqs []OTPRecoveryRequest) {
	if len(reqs) == 0 {
		r.storage.Delete(otpRecoveryKey)
		return
	}
	raw, err := json.Marshal(reqs)
	if err != nil {
		return
	}
	r.storage.Set(otpRecoveryKey, raw, otpRecoveryTTL)
}

// addOTPRecoveryRequest queues a recovery request; false when already queued
func (r *Router) addOTPRecoveryRequest(username string) bool {
	reqs := r.loadOTPRecoveryRequests()
	for _, req := range reqs {
		if req.Username == username {
			return false
		}
	}
	r.saveOTPRecoveryRequests(append(reqs, OTPRecoveryRequest{Username: username, RequestedAt: time.Now()}))
	return true
}

// removeOTPRecoveryRequest drops a queued request; false when absent
func (r *Router) removeOTPRecoveryRequest(username string) bool {
	reqs := r.loadOTPRecoveryRequests()
	kept := reqs[:0]
	for _, req := range reqs {
		if req.Username != username {
			kept = append(kept, req)
		}
	}
	if len(kept) == len(reqs) {
		return false
	}
	r.saveOTPRecoveryRequests(kept)
	return true
}
