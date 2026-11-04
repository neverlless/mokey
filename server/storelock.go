// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

// Locking for the read-modify-write cycles on storage keys holding JSON
// lists (session index, group requests, OTP recovery queue) and the audit
// sequence. On redis the lock is a SET NX key shared by all replicas; on
// memory and sqlite3 (one process) a mutex per key is enough.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/storage/redis/v3"
	goredis "github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	storeLockPrefix = "lock-"
	// a holder only does a few storage calls; the TTL frees the lock of a
	// replica that died while holding it
	storeLockTTL  = 5 * time.Second
	storeLockWait = storeLockTTL + time.Second
)

var errStoreLockTimeout = errors.New("timed out waiting for storage lock")

// compare-and-delete: never release a lock that expired and was taken by
// another replica
var storeUnlockScript = `if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end`

type storeLock struct {
	storage fiber.Storage
	rdb     goredis.UniversalClient // nil unless the storage driver is redis
	local   sync.Map                // key -> *sync.Mutex
}

func newStoreLock(storage fiber.Storage) *storeLock {
	l := &storeLock{storage: storage}
	if rs, ok := storage.(*redis.Storage); ok {
		l.rdb = rs.Conn()
	}
	return l
}

// hold takes the lock for key and returns its release. When the lock
// cannot be taken (Redis down, or a holder stuck past storeLockWait) the
// caller proceeds unlocked, as before locking existed: every guarded site
// rewrites an index whose worst lost update is a stale or missing list
// entry, while refusing would block logins, logouts and session
// revocation.
func (l *storeLock) hold(key string) (release func()) {
	// on redis too: one waiter per replica polls Redis instead of every
	// request
	m, _ := l.local.LoadOrStore(key, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	if l.rdb == nil {
		return mu.Unlock
	}

	token, err := l.acquire(key)
	if err != nil {
		log.WithFields(log.Fields{
			"key": key,
			"err": err,
		}).Warn("Proceeding without storage lock")
		return mu.Unlock
	}
	return func() {
		l.release(key, token)
		mu.Unlock()
	}
}

func (l *storeLock) acquire(key string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	ctx := context.Background()
	deadline := time.Now().Add(storeLockWait)
	backoff := 2 * time.Millisecond
	for {
		ok, err := l.rdb.SetNX(ctx, storeLockPrefix+key, token, storeLockTTL).Result()
		if err != nil {
			return "", err
		}
		if ok {
			return token, nil
		}
		if time.Now().After(deadline) {
			return "", errStoreLockTimeout
		}
		time.Sleep(backoff)
		backoff = min(backoff*2, 20*time.Millisecond)
	}
}

func (l *storeLock) release(key, token string) {
	if err := l.rdb.Eval(context.Background(), storeUnlockScript, []string{storeLockPrefix + key}, token).Err(); err != nil {
		log.WithFields(log.Fields{
			"key": key,
			"err": err,
		}).Warn("Failed to release storage lock, it expires on its own")
	}
}

// incr atomically increments the integer counter stored at key and returns
// the new value
func (l *storeLock) incr(key string) (int64, error) {
	if l.rdb != nil {
		return l.rdb.Incr(context.Background(), key).Result()
	}

	defer l.hold(key)()
	seq := int64(0)
	if raw, _ := l.storage.Get(key); raw != nil {
		seq, _ = strconv.ParseInt(string(raw), 10, 64)
	}
	seq++
	return seq, l.storage.Set(key, []byte(strconv.FormatInt(seq, 10)), 0)
}
