package server

import (
	"github.com/neverlless/goipa/ipatest"
	"net/url"
	"strings"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestSlackMessageForUsernameReminderIncludesUsernames(t *testing.T) {
	assert := assert.New(t)
	user := &ipa.User{First: "Walter"}
	data := map[string]interface{}{
		"site_name": "Test",
		"usernames": []string{"walter", "heisenberg"},
	}

	msg := slackMessageFor("username-reminder", "Your username", data, user)

	assert.Contains(msg, "walter")
	assert.Contains(msg, "heisenberg")
}

// #28: some mail gateways only let a message through when the subject
// carries a marker, so both affixes have to be configurable
func TestEmailSubjectAffixes(t *testing.T) {
	subjectOf := func(raw string) string {
		for _, line := range strings.Split(raw, "\n") {
			if after, ok := strings.CutPrefix(line, "Subject: "); ok {
				return strings.TrimSpace(after)
			}
		}
		return ""
	}

	// the forgot-password mail is sent synchronously inside the handler
	sendOne := func(t *testing.T, configure func()) string {
		t.Helper()
		app, _, fake := newTestAppWith(t, func() {
			viper.Set("accounts.enable_captcha", false)
			viper.Set("site.name", "Acme Widgets")
			configure()
		})
		sink := newFakeSMTP(t)
		fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

		tc := newTestClient(t, app)
		tc.getCSRF("/auth/forgotpw")
		tc.postForm("/auth/forgotpw", url.Values{"username": {"walter"}}, nil)

		if len(sink.all()) == 0 {
			t.Fatal("no email delivered")
		}
		return subjectOf(sink.all()[0])
	}

	t.Run("defaults to the site name in brackets", func(t *testing.T) {
		subject := sendOne(t, func() {})
		assert.True(t, strings.HasPrefix(subject, "[Acme Widgets] "), "got %q", subject)
	})

	t.Run("prefix and suffix are configurable", func(t *testing.T) {
		subject := sendOne(t, func() {
			viper.Set("email.subject_prefix", "IDM: ")
			viper.Set("email.subject_suffix", " [SECURE]")
		})
		assert.True(t, strings.HasPrefix(subject, "IDM: "), "got %q", subject)
		assert.True(t, strings.HasSuffix(subject, " [SECURE]"), "got %q", subject)
		assert.NotContains(t, subject, "[Acme Widgets]")
	})

	t.Run("an explicitly empty prefix drops it entirely", func(t *testing.T) {
		subject := sendOne(t, func() { viper.Set("email.subject_prefix", "") })
		assert.NotContains(t, subject, "[Acme Widgets]")
	})
}

func TestSlackMessageForInviteHasInviterAndLink(t *testing.T) {
	data := map[string]interface{}{
		"site_name":    "Acme",
		"inviter":      "Walter White",
		"link":         "https://sso.example.com/auth/invite/tok",
		"link_expires": "1 day",
	}
	msg := slackMessageFor("invite", "invited", data, &ipa.User{})
	assert.Contains(t, msg, "Walter White")
	assert.Contains(t, msg, "<https://sso.example.com/auth/invite/tok|")
	assert.Contains(t, msg, "1 day")
}

func TestSlackMessageForTokenMailsCarryLink(t *testing.T) {
	for _, tmpl := range []string{"account-verify", "email-change", "otprecovery-confirm", "password-reset"} {
		data := map[string]interface{}{"site_name": "Acme", "link": "https://sso.example.com/x", "link_expires": "1 hour"}
		msg := slackMessageFor(tmpl, "subject", data, &ipa.User{First: "Walter"})
		assert.Contains(t, msg, "<https://sso.example.com/x|", tmpl)
	}
}

func TestSlackMessageEscapesNames(t *testing.T) {
	data := map[string]interface{}{
		"site_name":    "A<b>&*c",
		"inviter":      "<!channel> *x*",
		"link":         "https://sso.example.com/x",
		"link_expires": "1 day",
	}
	for _, tmpl := range []string{"invite", "password-reset", "account-verify"} {
		msg := slackMessageFor(tmpl, "s", data, &ipa.User{First: "<!here>"})
		assert.NotContains(t, msg, "<b>", tmpl)
		assert.NotContains(t, msg, "<!channel>", tmpl)
		assert.NotContains(t, msg, "<!here>", tmpl)
		assert.NotContains(t, msg, "*c", tmpl)
		assert.NotContains(t, msg, "*x*", tmpl)
		assert.Contains(t, msg, "&lt;b&gt;&amp;", tmpl)
	}
}

func TestSlackUsernamesAreCodeSpans(t *testing.T) {
	data := map[string]interface{}{"site_name": "Acme", "usernames": []string{"john_doe", "<!channel>"}}
	msg := slackMessageFor("username-reminder", "s", data, &ipa.User{})
	assert.Contains(t, msg, "`john_doe`")
	assert.NotContains(t, msg, "\u200b")
	assert.NotContains(t, msg, "<!channel>")
	assert.Contains(t, msg, "`&lt;!channel&gt;`")

	inv := slackMessageFor("invite", "s", map[string]interface{}{"site_name": "Acme", "inviter": "W", "link": "https://x/y", "link_expires": "1 day", "preset_username": "kim_w"}, &ipa.User{})
	assert.Contains(t, inv, "`kim_w`")
}
