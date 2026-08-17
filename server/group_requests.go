// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"encoding/json"
	"time"
)

// Join-request queue: one storage key per group holding a JSON list,
// same durability as the session index (memory/sqlite3/redis).
// ponytail: no cross-instance lock — a concurrent approve loses at worst
// a redundant queue write; group membership itself is idempotent in IPA.

const (
	groupRequestsPrefix = "grouprequests-"
	groupRequestsTTL    = 30 * 24 * time.Hour
)

type GroupRequest struct {
	Username    string    `json:"username"`
	RequestedAt time.Time `json:"requested_at"`
}

func (r *Router) loadGroupRequests(group string) []GroupRequest {
	raw, err := r.storage.Get(groupRequestsPrefix + group)
	if err != nil || raw == nil {
		return nil
	}
	var reqs []GroupRequest
	if err := json.Unmarshal(raw, &reqs); err != nil {
		return nil
	}
	return reqs
}

func (r *Router) saveGroupRequests(group string, reqs []GroupRequest) {
	if len(reqs) == 0 {
		r.storage.Delete(groupRequestsPrefix + group)
		return
	}
	raw, err := json.Marshal(reqs)
	if err != nil {
		return
	}
	r.storage.Set(groupRequestsPrefix+group, raw, groupRequestsTTL)
}

// addGroupRequest queues a join request; false when already queued
func (r *Router) addGroupRequest(group, username string) bool {
	reqs := r.loadGroupRequests(group)
	for _, req := range reqs {
		if req.Username == username {
			return false
		}
	}
	r.saveGroupRequests(group, append(reqs, GroupRequest{Username: username, RequestedAt: time.Now()}))
	return true
}

// removeGroupRequest drops a queued request; false when absent
func (r *Router) removeGroupRequest(group, username string) bool {
	reqs := r.loadGroupRequests(group)
	kept := reqs[:0]
	for _, req := range reqs {
		if req.Username != username {
			kept = append(kept, req)
		}
	}
	if len(kept) == len(reqs) {
		return false
	}
	r.saveGroupRequests(group, kept)
	return true
}
