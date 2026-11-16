package server

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/storage/memory/v2"
	"github.com/gofiber/storage/redis/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func lockedRouter(storage fiber.Storage) *Router {
	return &Router{storage: storage, lock: newStoreLock(storage)}
}

// hammer runs n concurrent queue additions and audit increments, spread
// round-robin over the given routers (one per simulated replica)
func hammer(t *testing.T, n int, routers ...*Router) {
	t.Helper()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		r := routers[i%len(routers)]
		wg.Add(2)
		go func() {
			defer wg.Done()
			assert.True(t, r.addOTPRecoveryRequest(fmt.Sprintf("user%d", i)))
		}()
		go func() {
			defer wg.Done()
			_, err := r.lock.incr(auditSeqKey)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}

func TestStoreLockNoLostUpdates(t *testing.T) {
	r := lockedRouter(memory.New())
	hammer(t, 200, r)

	assert.Len(t, r.loadOTPRecoveryRequests(), 200)
	seq, err := r.storage.Get(auditSeqKey)
	require.NoError(t, err)
	assert.Equal(t, "200", string(seq))
}

// Two storage instances on one Redis stand in for two mokey replicas.
// MOKEY_TEST_REDIS_URL=redis://127.0.0.1:6390/15 — the database is flushed.
func TestStoreLockRedisReplicas(t *testing.T) {
	url := os.Getenv("MOKEY_TEST_REDIS_URL")
	if url == "" {
		t.Skip("MOKEY_TEST_REDIS_URL not set")
	}

	a := redis.New(redis.Config{URL: url, Reset: true})
	b := redis.New(redis.Config{URL: url})
	t.Cleanup(func() {
		_ = a.Reset()
		_ = a.Close()
		_ = b.Close()
	})

	ra, rb := lockedRouter(a), lockedRouter(b)
	require.NotNil(t, ra.lock.rdb)
	hammer(t, 200, ra, rb)

	assert.Len(t, rb.loadOTPRecoveryRequests(), 200)
	seq, err := a.Get(auditSeqKey)
	require.NoError(t, err)
	assert.Equal(t, "200", string(seq))

	// a lock that expired and was taken by another replica survives the
	// first holder's release
	release := ra.lock.hold("k")
	require.NoError(t, a.Conn().Set(context.Background(), storeLockPrefix+"k", "other", time.Minute).Err())
	release()
	v, err := a.Get(storeLockPrefix + "k")
	require.NoError(t, err)
	assert.Equal(t, "other", string(v))
}

// two routers on one storage stand in for two replicas
func TestSweepLeaseOneReplicaPerInterval(t *testing.T) {
	shared := memory.New()
	ra, rb := lockedRouter(shared), lockedRouter(shared)
	interval := 2 * time.Second

	assert.True(t, ra.lock.lease("sweep", interval))
	assert.False(t, rb.lock.lease("sweep", interval), "the other replica skips this run")
	assert.False(t, ra.lock.lease("sweep", interval))
	assert.True(t, rb.lock.lease("other-sweep", interval), "leases are per sweep")

	// the lease ends before the next interval, so either replica runs it
	assert.Eventually(t, func() bool { return rb.lock.lease("sweep", interval) }, 2*interval, 50*time.Millisecond)
}

func TestSweepLeaseRedisReplicas(t *testing.T) {
	url := os.Getenv("MOKEY_TEST_REDIS_URL")
	if url == "" {
		t.Skip("MOKEY_TEST_REDIS_URL not set")
	}

	a := redis.New(redis.Config{URL: url, Reset: true})
	b := redis.New(redis.Config{URL: url})
	t.Cleanup(func() {
		_ = a.Reset()
		_ = a.Close()
		_ = b.Close()
	})
	ra, rb := lockedRouter(a), lockedRouter(b)

	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		r := []*Router{ra, rb}[i%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.lock.lease("sweep", time.Second) {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), won.Load())
	assert.Eventually(t, func() bool { return rb.lock.lease("sweep", time.Second) }, 2*time.Second, 50*time.Millisecond)
}

func localLocks(l *storeLock) (n int) {
	l.local.Range(func(any, any) bool { n++; return true })
	return n
}

// concurrent takes of one key hand the value out once, and client-chosen
// keys leave no per-key state behind
func takeOnce(t *testing.T, locks ...*storeLock) {
	t.Helper()
	for k := range 20 {
		key := fmt.Sprintf("take-%d", k)
		require.NoError(t, locks[0].storage.Set(key, []byte("v"), time.Minute))
		var got atomic.Int32
		var wg sync.WaitGroup
		for i := range 20 {
			l := locks[i%len(locks)]
			wg.Add(1)
			go func() {
				defer wg.Done()
				raw, err := l.take(key)
				assert.NoError(t, err)
				if raw != nil {
					assert.Equal(t, "v", string(raw))
					got.Add(1)
				}
			}()
		}
		wg.Wait()
		assert.Equal(t, int32(1), got.Load(), key)
	}
	for _, l := range locks {
		assert.Zero(t, localLocks(l))
	}
	raw, err := locks[0].take("missing")
	assert.NoError(t, err)
	assert.Nil(t, raw)
}

func TestStoreTakeOnce(t *testing.T) {
	takeOnce(t, newStoreLock(memory.New()))
}

func TestStoreTakeOnceRedisReplicas(t *testing.T) {
	url := os.Getenv("MOKEY_TEST_REDIS_URL")
	if url == "" {
		t.Skip("MOKEY_TEST_REDIS_URL not set")
	}
	a := redis.New(redis.Config{URL: url, Reset: true})
	b := redis.New(redis.Config{URL: url})
	t.Cleanup(func() {
		_ = a.Reset()
		_ = a.Close()
		_ = b.Close()
	})
	takeOnce(t, newStoreLock(a), newStoreLock(b))
}
