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
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/storage/redis/v3"
	goredis "github.com/redis/go-redis/v9"
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
	takeMu  sync.Mutex
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
	release, err := l.holdStrict(key)
	if err != nil {
		slog.Warn("Proceeding without storage lock",
			"key", key,
			"err", err,
		)
		// the per-process mutex is not held after a failure
		m, _ := l.local.LoadOrStore(key, &sync.Mutex{})
		mu := m.(*sync.Mutex)
		mu.Lock()
		return mu.Unlock
	}
	return release
}

// holdStrict is hold for data where a lost update is not acceptable: when
// the lock cannot be taken it returns the error and holds nothing.
func (l *storeLock) holdStrict(key string) (release func(), err error) {
	// on redis too: one waiter per replica polls Redis instead of every
	// request
	m, _ := l.local.LoadOrStore(key, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	if l.rdb == nil {
		return mu.Unlock, nil
	}

	token, err := l.acquire(key)
	if err != nil {
		mu.Unlock()
		return nil, err
	}
	return func() {
		l.release(key, token)
		mu.Unlock()
	}, nil
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
		slog.Warn("Failed to release storage lock, it expires on its own",
			"key", key,
			"err", err,
		)
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

const leasePrefix = "lease-"

// lease reports whether this replica runs the periodic job name now: the
// first replica to call it holds lease-<name> for 9/10 of the interval and
// the others skip their run. In one process the lease has ended by the next
// run; a lease kept in redis or sqlite3 outlives a restart, so the first run
// after one may be skipped and the sweep then runs up to an interval late.
func (l *storeLock) lease(name string, interval time.Duration) bool {
	_, ok, err := l.claim(leasePrefix+name, interval*9/10)
	if err != nil {
		slog.Warn("Skipping this run, storage unavailable", "job", name, "err", err)
	}
	return ok
}

// claim takes key for ttl unless another caller, on any replica, holds it.
// release frees it before the ttl; the ttl frees the claim of a replica
// that died holding it. release leaves a claim that expired and was taken
// by someone else.
func (l *storeLock) claim(key string, ttl time.Duration) (release func(), ok bool, err error) {
	token, ok, err := l.claimToken(key, ttl)
	if !ok {
		return nil, false, err
	}
	return func() { l.unclaim(key, token) }, true, nil
}

// claimKept is claim for a run that may outlast ttl: the claim is renewed
// every ttl/3 until release.
func (l *storeLock) claimKept(key string, ttl time.Duration) (release func(), ok bool, err error) {
	token, ok, err := l.claimToken(key, ttl)
	if !ok {
		return nil, false, err
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(ttl / 3)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if !l.renew(key, token, ttl) {
					return
				}
			}
		}
	}()
	return sync.OnceFunc(func() {
		close(stop)
		<-done
		l.unclaim(key, token)
	}), true, nil
}

func (l *storeLock) claimToken(key string, ttl time.Duration) (string, bool, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", false, err
	}
	token := hex.EncodeToString(b)

	unlock, err := l.holdStrict(key)
	if err != nil {
		return "", false, err
	}
	defer unlock()

	held, err := l.storage.Get(key)
	if err != nil || held != nil {
		return "", false, err
	}
	if err := l.storage.Set(key, []byte(token), ttl); err != nil {
		return "", false, err
	}
	return token, true, nil
}

// renew extends the claim while it is still ours; false once it is lost.
func (l *storeLock) renew(key, token string, ttl time.Duration) bool {
	unlock, err := l.holdStrict(key)
	if err != nil {
		slog.Warn("Failed to renew a run lock, retrying", "key", key, "err", err)
		return true
	}
	defer unlock()
	held, err := l.storage.Get(key)
	if err == nil && string(held) != token {
		slog.Warn("Run lock lost, another run may start", "key", key)
		return false
	}
	if err == nil {
		err = l.storage.Set(key, []byte(token), ttl)
	}
	if err != nil {
		slog.Warn("Failed to renew a run lock, retrying", "key", key, "err", err)
	}
	return true
}

func (l *storeLock) unclaim(key, token string) {
	unlock, err := l.holdStrict(key)
	if err != nil {
		slog.Warn("Failed to release a run lock, it expires on its own", "key", key, "err", err)
		return
	}
	defer unlock()
	held, err := l.storage.Get(key)
	if err == nil && string(held) == token {
		err = l.storage.Delete(key)
	}
	if err != nil {
		slog.Warn("Failed to release a run lock, it expires on its own", "key", key, "err", err)
	}
}

// get-and-delete in one step; GETDEL needs Redis 6.2
var storeTakeScript = `local v = redis.call("get", KEYS[1]) if v then redis.call("del", KEYS[1]) end return v`

// take reads and deletes key in one atomic step, so a single-use value
// (captcha, forward-auth code) is handed out at most once even across
// replicas. raw is nil for a missing key. Keys come from clients, so no
// per-key lock: one mutex per process serves memory and sqlite3.
func (l *storeLock) take(key string) (raw []byte, err error) {
	if l.rdb != nil {
		v, err := l.rdb.Eval(context.Background(), storeTakeScript, []string{key}).Text()
		if errors.Is(err, goredis.Nil) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return []byte(v), nil
	}

	l.takeMu.Lock()
	defer l.takeMu.Unlock()
	raw, err = l.storage.Get(key)
	if err != nil || raw == nil {
		return nil, err
	}
	if err := l.storage.Delete(key); err != nil {
		return nil, err
	}
	return raw, nil
}
