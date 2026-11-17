package server

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func userCfg() *lifecycleConfig {
	return &lifecycleConfig{Reminders: []int{30, 7, 1}, MaxChanges: 50}
}

func profileFor(t *testing.T, cfg *lifecycleConfig, manager string, expires time.Time) string {
	t.Helper()
	tc, _, d, _ := newSponsorApp(t, cfg)
	d.add("walter", ipatest.User{First: "Walter", Last: "White"}, manager, expires)
	d.add("skyler", ipatest.User{First: "Skyler", Last: "White"}, "", time.Time{})
	tc.login("walter", spSecret)
	return readBody(t, tc.get("/"))
}

func TestUserNoExpiryNoRows(t *testing.T) {
	body := profileFor(t, userCfg(), "skyler", time.Time{})
	assert.NotContains(t, body, T("account.valid_until"))
	assert.NotContains(t, body, T("account.expires_banner_part1"))
}

func TestUserBannerNamesSponsor(t *testing.T) {
	body := profileFor(t, userCfg(), "skyler", time.Now().Add(20*24*time.Hour+time.Hour))
	assert.Contains(t, body, T("account.expires_banner_part1"))
	assert.Contains(t, body, "Skyler White")
	assert.Contains(t, body, T("account.valid_until"))
	assert.Contains(t, body, "mokey-pill is-warn")
	assert.Contains(t, body, ">in 21 days<")
}

func TestUserBannerWithoutSponsor(t *testing.T) {
	body := profileFor(t, userCfg(), "", time.Now().Add(20*24*time.Hour))
	assert.Contains(t, body, T("account.expires_banner_admin"))
	assert.NotContains(t, body, T("account.sponsor"))
}

func TestUserFarExpiryRowsOnly(t *testing.T) {
	body := profileFor(t, userCfg(), "skyler", time.Now().Add(60*24*time.Hour))
	assert.Contains(t, body, T("account.valid_until"))
	assert.Contains(t, body, T("account.sponsor"))
	assert.NotContains(t, body, T("account.expires_banner_part1"))
	assert.NotContains(t, body, "mokey-pill is-warn")
}

func TestUserFactsWithLifecycleOff(t *testing.T) {
	body := profileFor(t, nil, "", time.Now().Add(5*24*time.Hour))
	assert.Contains(t, body, T("account.valid_until"))
	assert.NotContains(t, body, T("account.expires_banner_part1"))
	assert.NotContains(t, body, "mokey-pill is-warn")
}

func TestUserSponsorLookupFailureHidesSponsor(t *testing.T) {
	body := profileFor(t, userCfg(), "ghost", time.Now().Add(20*24*time.Hour))
	assert.Contains(t, body, T("account.valid_until"))
	assert.Contains(t, body, T("account.expires_banner_admin"))
	assert.NotContains(t, body, T("account.sponsor"))
}

// Day uses the server's local zone. The zone is set through TZ in a child
// test process: writing time.Local here races with goroutines that other
// tests leave running (loggers, fasthttp's date cache).
func TestDayFormatsInLocalTime(t *testing.T) {
	if os.Getenv("MOKEY_TEST_DAY_CHILD") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDayFormatsInLocalTime$", "-test.count=1") // #nosec G204 -- the test binary itself
		cmd.Env = append(os.Environ(), "MOKEY_TEST_DAY_CHILD=1", "TZ=Asia/Karachi")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %s\n%s", err, out)
		}
		return
	}
	viper.Reset()
	SetDefaults()
	t.Cleanup(viper.Reset)
	require.NoError(t, LoadTranslations())
	_, off := time.Now().Zone()
	require.Equal(t, 5*3600, off, "TZ=Asia/Karachi not loaded")
	f := languageFuncs("english")["Day"].(func(time.Time) string)
	assert.Equal(t, "Dec 3, 2026", f(time.Date(2026, 12, 2, 22, 0, 0, 0, time.UTC)))
}
