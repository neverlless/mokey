package server

import (
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
	shared := memory.New()
	a, b := storageCaptchaStore{shared}, storageCaptchaStore{shared}

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
