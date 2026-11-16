package server

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// lastSeenWriteFails refuses writes of the sign-in timestamps only
type lastSeenWriteFails struct{ fiber.Storage }

func (s *lastSeenWriteFails) Set(key string, val []byte, exp time.Duration) error {
	if strings.HasPrefix(key, lastSeenPrefix) {
		return errors.New("storage backend down")
	}
	return s.Storage.Set(key, val, exp)
}

func TestPortalLoginRecordsSignIn(t *testing.T) {
	app, router, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	assert.True(t, router.lastSignIn("walter").IsZero())

	newTestClient(t, app).login("walter", "Secret123!")
	assert.WithinDuration(t, time.Now(), router.lastSignIn("walter"), time.Minute)
}

func TestSignInSurvivesStorageFailure(t *testing.T) {
	app, router, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	router.storage = &lastSeenWriteFails{router.storage}

	// login asserts 204
	newTestClient(t, app).login("walter", "Secret123!")
	assert.True(t, router.lastSignIn("walter").IsZero())
}

func TestOIDCLoginRecordsSignIn(t *testing.T) {
	assert := assert.New(t)
	hy := newFakeHydra()
	t.Cleanup(hy.Close)
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("hydra.admin_url", hy.srv.URL)
		viper.Set("hydra.login_timeout", int64(3600))
	})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	tc := newTestClient(t, app)

	// hydra remembers walter: skip straight through
	hy.seedLogin("chal-skip", "walter", true)
	resp := tc.get("/oauth/login?login_challenge=chal-skip")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.WithinDuration(time.Now(), router.lastSignIn("walter"), time.Minute)

	// signed in to the portal already: the challenge is accepted at once
	tc.login("walter", "Secret123!")
	assert.NoError(router.storage.Delete(lastSeenPrefix + "walter"))
	hy.seedLogin("chal-session", "", false)
	resp = tc.get("/oauth/login?login_challenge=chal-session")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.WithinDuration(time.Now(), router.lastSignIn("walter"), time.Minute)
}
