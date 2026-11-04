package server

import (
	"crypto/sha1" // #nosec G505 -- mirrors the Pwned Passwords key
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

const pwnedFixture = "NewSecret456!"

// fakePwned serves the range API, answering every prefix with body(suffix)
// where suffix is pwnedFixture's hash suffix. It returns the hit count.
func fakePwned(t *testing.T, handler func(w http.ResponseWriter, suffix string)) *atomic.Int32 {
	t.Helper()
	sum := sha1.Sum([]byte(pwnedFixture)) // #nosec G401 -- test fixture
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		assert.Equal(t, "/range/"+hash[:5], r.URL.Path)
		assert.Equal(t, "true", r.Header.Get("Add-Padding"))
		assert.Equal(t, "mokey", r.Header.Get("User-Agent"))
		handler(w, hash[5:])
	}))
	t.Cleanup(srv.Close)

	oldURL := pwnedRangeURL
	pwnedRangeURL = srv.URL + "/range/"
	t.Cleanup(func() { pwnedRangeURL = oldURL })
	return &hits
}

func enableBreachCheck(t *testing.T) {
	viper.Reset()
	SetDefaults()
	viper.Set("accounts.check_breached_passwords", true)
	t.Cleanup(func() {
		viper.Reset()
		SetDefaults()
	})
}

func TestBreachedPasswordRefused(t *testing.T) {
	enableBreachCheck(t)
	fakePwned(t, func(w http.ResponseWriter, suffix string) {
		fmt.Fprintf(w, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n%s:42\r\n", suffix)
	})

	err := validatePassword("english", pwnedFixture, pwnedFixture, "walter", nil)
	assert.EqualError(t, err, T("password.breached"))
}

func TestBreachedPasswordNotPresent(t *testing.T) {
	enableBreachCheck(t)
	hits := fakePwned(t, func(w http.ResponseWriter, _ string) {
		fmt.Fprint(w, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n")
	})

	assert.NoError(t, validatePassword("english", pwnedFixture, pwnedFixture, "walter", nil))
	assert.EqualValues(t, 1, hits.Load())
}

func TestBreachedPasswordPaddingIgnored(t *testing.T) {
	enableBreachCheck(t)
	fakePwned(t, func(w http.ResponseWriter, suffix string) {
		fmt.Fprintf(w, "%s:0\r\n", suffix)
	})

	assert.NoError(t, validatePassword("english", pwnedFixture, pwnedFixture, "walter", nil))
}

func TestBreachedPasswordFailsOpen(t *testing.T) {
	enableBreachCheck(t)

	t.Run("server error", func(t *testing.T) {
		fakePwned(t, func(w http.ResponseWriter, suffix string) {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "%s:42\r\n", suffix)
		})
		assert.NoError(t, validatePassword("english", pwnedFixture, pwnedFixture, "walter", nil))
	})

	t.Run("timeout", func(t *testing.T) {
		oldTimeout := pwnedClient.Timeout
		pwnedClient.Timeout = 50 * time.Millisecond
		t.Cleanup(func() { pwnedClient.Timeout = oldTimeout })
		fakePwned(t, func(w http.ResponseWriter, suffix string) {
			time.Sleep(200 * time.Millisecond)
			fmt.Fprintf(w, "%s:42\r\n", suffix)
		})
		assert.NoError(t, validatePassword("english", pwnedFixture, pwnedFixture, "walter", nil))
	})
}

func TestBreachedPasswordCheckOffByDefault(t *testing.T) {
	viper.Reset()
	SetDefaults()
	hits := fakePwned(t, func(w http.ResponseWriter, suffix string) {
		fmt.Fprintf(w, "%s:42\r\n", suffix)
	})

	assert.NoError(t, validatePassword("english", pwnedFixture, pwnedFixture, "walter", nil))
	assert.Zero(t, hits.Load())
}

func TestBreachedPasswordSkippedWhenPolicyFails(t *testing.T) {
	enableBreachCheck(t)
	hits := fakePwned(t, func(w http.ResponseWriter, suffix string) {
		fmt.Fprintf(w, "%s:42\r\n", suffix)
	})

	assert.Error(t, validatePassword("english", "short", "short", "walter", nil))
	assert.Zero(t, hits.Load())
}
