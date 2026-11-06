package server

import (
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestSecurityState(t *testing.T) {
	for _, c := range []struct {
		otpOnly bool
		count   int
		want    string
	}{
		{true, 0, "protected"},
		{true, 2, "protected"},
		{false, 1, "turn_on"},
		{false, 0, "password_only"},
	} {
		assert.Equal(t, c.want, securityState(c.otpOnly, c.count), "otpOnly=%v count=%d", c.otpOnly, c.count)
	}
}

func TestSecurityHubStates(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	body := securityPage(t, tc)
	assert.Contains(body, T("security.state_password_only_title"))
	assert.Contains(body, `href="/otp"`)
	assert.Regexp(`(?s)<button[^>]*\sdisabled\s[^>]*data-hx-post="/security/mfa/enable"`, body)
	assert.NotContains(body, `data-count="otp"`)

	fake.AddOTPToken(ipatest.OTPToken{Owner: "walter"})
	body = securityPage(t, tc)
	assert.Contains(body, T("security.state_turn_on_title"))
	assert.NotRegexp(`(?s)<button[^>]*\sdisabled\s[^>]*data-hx-post="/security/mfa/enable"`, body)
	assert.Contains(body, `data-count="otp"`)
}

func TestSecurityHubSurvivesTokenListError(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	fake.Handle("otptoken_find", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, ipa.ErrNotFound
	})

	body := securityPage(t, tc)
	assert.NotContains(body, `data-count="otp"`)
	assert.Contains(body, T("security.sessions_title"))
}

func TestSecurityHubKeepsRequireMFAAlert(t *testing.T) {
	app, _, fake := newTestAppWith(t, func() { viper.Set("accounts.require_mfa", true) })
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	assert.Contains(t, securityPage(t, tc), T("common.must_enable_2fa"))
}
