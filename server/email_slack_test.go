package server

import (
	"net/url"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	ipa "github.com/ubccr/goipa"
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
		fake.addUser("walter", &fakeUser{Password: "Secret123!"})

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
