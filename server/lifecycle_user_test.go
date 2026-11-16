package server

import (
	"testing"
	"time"

	"github.com/neverlless/goipa/ipatest"
	"github.com/stretchr/testify/assert"
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

func TestDayFormatsInLocalTime(t *testing.T) {
	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	time.Local = time.FixedZone("plus5", 5*3600)
	f := languageFuncs("english")["Day"].(func(time.Time) string)
	assert.Equal(t, "Dec 3, 2026", f(time.Date(2026, 12, 2, 22, 0, 0, 0, time.UTC)))
}
