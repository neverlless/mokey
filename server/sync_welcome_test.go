package server

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var resetLinkPattern = regexp.MustCompile(`/auth/resetpw/([A-Za-z0-9_-]+)`)

func unwrapQP(msg string) string {
	return strings.NewReplacer("=\r\n", "", "=\n", "").Replace(msg)
}

// mailedToken pulls the reset token out of a quoted-printable message.
func mailedToken(t *testing.T, msg string) string {
	t.Helper()
	m := resetLinkPattern.FindStringSubmatch(unwrapQP(msg))
	require.NotNil(t, m, msg)
	return m[1]
}

func welcomeApp(t *testing.T, ttl time.Duration) (*fiber.App, *Router, *ipatest.Server, *fakeSMTP) {
	t.Helper()
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
		viper.Set("email.base_url", "https://portal.example.org")
	})
	sink := newFakeSMTP(t)
	fake.AddGroup("google2ipa-managed", ipatest.Group{})
	router.sync = &syncConfig{
		ManagedGroup: "google2ipa-managed", Username: "local_part", MaxUsernameLength: 32,
		Concurrency: 1, MaxEventsPerRun: 50, MaxDisablePercent: 20,
		WelcomeMail: true, WelcomeLinkTTL: ttl,
	}
	router.adminClient = fake.ClientAs("admin")
	router.lock = newStoreLock(router.storage)
	router.metrics = NewMetrics()
	router.syncSrc = &fakeSyncSource{users: []syncSourceUser{{Email: "newbie@example.org", GivenName: "G", FamilyName: "newbie"}}}
	return app, router, fake, sink
}

func TestSyncWelcomeLinkSetsPassword(t *testing.T) {
	app, router, fake, sink := welcomeApp(t, 7*24*time.Hour)

	res, err := router.syncRun(t.Context(), time.Now(), "", false)
	require.NoError(t, err)
	require.Empty(t, res.Errors)

	msgs := sink.all()
	require.Len(t, msgs, 1)
	token := mailedToken(t, msgs[0])
	assert.Contains(t, unwrapQP(msgs[0]), "https://portal.example.org/auth/resetpw/")

	tc := newTestClient(t, app)
	assert.Equal(t, fiber.StatusOK, tc.get("/auth/resetpw/"+token).StatusCode)
	tc.getCSRF("/auth/resetpw/" + token)
	resp := tc.postForm("/auth/resetpw/"+token, url.Values{
		"password":  {"NewSecret456!"},
		"password2": {"NewSecret456!"},
	}, nil)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.Equal(t, "NewSecret456!", fakeUser(fake, "newbie").Password)

	assert.Equal(t, fiber.StatusNotFound, tc.get("/auth/resetpw/"+token).StatusCode, "single-use")
	tc2 := newTestClient(t, app)
	tc2.login("newbie", "NewSecret456!")
}

func TestSyncWelcomeMailFailureIsRunError(t *testing.T) {
	_, router, fake, sink := welcomeApp(t, time.Hour)
	sink.rejectData = true

	res, err := router.syncRun(t.Context(), time.Now(), "", false)
	require.NoError(t, err)
	require.Len(t, res.Errors, 1)
	assert.Contains(t, res.Errors[0], "welcome mail newbie")
	assert.NotNil(t, fakeUser(fake, "newbie"), "no rollback")
	assert.Equal(t, 1, res.Applied["create"])
}

func TestSyncWelcomeLinkOutlivesDefaultTTL(t *testing.T) {
	_, router, _, sink := welcomeApp(t, 7*24*time.Hour)
	viper.Set("email.token_max_age", 1)

	_, err := router.syncRun(t.Context(), time.Now(), "", false)
	require.NoError(t, err)
	time.Sleep(2100 * time.Millisecond)
	_, err = ParseToken(mailedToken(t, sink.all()[0]), TokenPasswordReset, router.storage)
	assert.NoError(t, err)
}

func TestSyncWelcomeMailOffByDefault(t *testing.T) {
	_, router, _, sink := welcomeApp(t, time.Hour)
	router.sync.WelcomeMail = false
	_, err := router.syncRun(t.Context(), time.Now(), "", false)
	require.NoError(t, err)
	assert.Zero(t, sink.count())
}
