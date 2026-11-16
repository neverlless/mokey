package server

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dchest/captcha"
	"github.com/gofiber/storage/memory/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func digitsString(d []byte) string {
	s := make([]byte, len(d))
	for i, v := range d {
		s[i] = '0' + v
	}
	return string(s)
}

// two replicas: each installs its own store on one shared storage
func TestCaptchaSharedAcrossReplicas(t *testing.T) {
	t.Cleanup(func() { captcha.SetCustomStore(captcha.NewMemoryStore(captcha.CollectNum, captcha.Expiration)) })
	shared := memory.New()
	a, b := storageCaptchaStore{newStoreLock(shared)}, storageCaptchaStore{newStoreLock(shared)}

	captcha.SetCustomStore(a)
	id := captcha.New()
	sol := digitsString(a.Get(id, false))
	require.NotEmpty(t, sol)

	captcha.SetCustomStore(b)
	assert.False(t, captcha.VerifyString(id, "x"+sol), "a wrong answer fails")
	// dchest deletes on any verification attempt, so mint a fresh one
	captcha.SetCustomStore(a)
	id = captcha.New()
	sol = digitsString(a.Get(id, false))

	captcha.SetCustomStore(b)
	assert.True(t, captcha.VerifyString(id, sol), "issued on a, verified on b")
	assert.False(t, captcha.VerifyString(id, sol), "single use")
	captcha.SetCustomStore(a)
	assert.False(t, captcha.VerifyString(id, sol), "single use on the other replica too")
}

func TestCaptchaSingleUseConcurrent(t *testing.T) {
	s := storageCaptchaStore{newStoreLock(memory.New())}
	s.Set("id", []byte{1, 2, 3})

	var got atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Get("id", true) != nil {
				got.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), got.Load())
}
