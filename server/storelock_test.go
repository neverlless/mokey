package server

import (
	"context"
	"fmt"
	"os"
	"sync"
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
