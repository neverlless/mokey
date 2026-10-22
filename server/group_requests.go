// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"
)

// Join-request queue: one storage key per group holding a JSON list,
// same durability as the session index (memory/sqlite3/redis).
// ponytail: no cross-instance lock — a concurrent approve loses at worst
// a redundant queue write; group membership itself is idempotent in IPA.

const (
	groupRequestsPrefix = "grouprequests-"
	groupRequestsTTL    = 30 * 24 * time.Hour

	groupRequestJoin  = "join"
	groupRequestLeave = "leave"
)

type GroupRequest struct {
	Username    string    `json:"username"`
	Type        string    `json:"type"`
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
	var err error
	if len(reqs) == 0 {
		err = r.storage.Delete(groupRequestsPrefix + group)
	} else {
		var raw []byte
		if raw, err = json.Marshal(reqs); err == nil {
			err = r.storage.Set(groupRequestsPrefix+group, raw, groupRequestsTTL)
		}
	}
	if err != nil {
		log.WithFields(log.Fields{
			"group": group,
			"err":   err,
		}).Error("Failed to save group requests")
	}
}

// addGroupRequest queues a join or leave request; false when already queued
func (r *Router) addGroupRequest(group, username, reqType string) bool {
	reqs := r.loadGroupRequests(group)
	for _, req := range reqs {
		if req.Username == username {
			return false
		}
	}
	r.saveGroupRequests(group, append(reqs, GroupRequest{Username: username, Type: reqType, RequestedAt: time.Now()}))
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
