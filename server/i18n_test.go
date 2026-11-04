package server

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// extraLanguages writes a russian (built-in code) and a german (declared
// code) translation file into a fresh site.translations_dir
func extraLanguages(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"russian.toml": `[duration]
minute_one = "%d минута"
minute_few = "%d минуты"
minute_many = "%d минут"
ago = "%s назад"
`,
		"german.toml": `language_code = "de"

[common]
username = "Benutzername"
`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	viper.Set("site.translations_dir", dir)
}

func TestMatchLanguage(t *testing.T) {
	defer viper.Reset()
	extraLanguages(t)
	viper.Set("site.languages", []string{"english", "dutch", "russian", "german"})
	assert.NoError(t, LoadTranslations())
	assert.Equal(t, "de", languageCodes["german"])

	for header, want := range map[string]string{
		"nl-NL,nl;q=0.9,en;q=0.8": "dutch",
		"en;q=0.5, nl;q=0.8":      "dutch",
		"ru-RU":                   "russian",
		"fr-FR, de;q=0.1":         "german",
		"DE-at":                   "german",
		"nl;q=0, en;q=0.1":        "english",
		"nl;q=bogus, ru;q=0.2":    "russian",
		"fr":                      "",
		"*":                       "",
		"":                        "",
	} {
		assert.Equal(t, want, matchLanguage(header), header)
	}
}

func TestSiteLanguagesConfig(t *testing.T) {
	defer viper.Reset()

	assert.NoError(t, LoadTranslations())
	assert.Equal(t, []string{"english"}, languages, "default_language alone unless site.languages is set")
	assert.Equal(t, "", matchLanguage("nl"))

	viper.Set("site.default_language", "dutch")
	viper.Set("site.languages", []string{"english"})
	assert.NoError(t, LoadTranslations())
	assert.Equal(t, []string{"dutch", "english"}, languages, "the default is always offered")

	viper.Set("site.languages", []string{"english", "klingon"})
	assert.ErrorContains(t, LoadTranslations(), "klingon")
}

func TestPageLanguage(t *testing.T) {
	t.Run("single language ignores Accept-Language", func(t *testing.T) {
		app, _, _ := newTestApp(t)
		resp := newTestClient(t, app).get("/auth/login", map[string]string{"Accept-Language": "nl"})
		body := readBody(t, resp)
		assert.Contains(t, body, `<html lang="en">`)
		assert.Contains(t, body, ">Username<")
		assert.Empty(t, resp.Header.Get("Vary"))
	})

	t.Run("offered languages follow Accept-Language", func(t *testing.T) {
		app, _, _ := newTestAppWith(t, func() {
			viper.Set("site.languages", []string{"english", "dutch"})
		})
		tc := newTestClient(t, app)

		resp := tc.get("/auth/login", map[string]string{"Accept-Language": "nl-BE,en;q=0.5"})
		body := readBody(t, resp)
		assert.Contains(t, body, `<html lang="nl">`)
		assert.Contains(t, body, ">Gebruikersnaam<")
		assert.Contains(t, resp.Header.Get("Vary"), "Accept-Language")

		body = readBody(t, tc.get("/auth/login", map[string]string{"Accept-Language": "fr"}))
		assert.Contains(t, body, `<html lang="en">`, "unsupported falls back to default_language")
		assert.Contains(t, body, ">Username<")
	})
}

func TestEmailLanguage(t *testing.T) {
	t.Run("request email follows the request", func(t *testing.T) {
		app, _, fake := newTestAppWith(t, func() {
			viper.Set("site.languages", []string{"english", "dutch"})
			viper.Set("accounts.enable_captcha", false)
		})
		sink := newFakeSMTP(t)
		fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

		tc := newTestClient(t, app)
		tc.getCSRF("/auth/forgotpw")
		tc.postForm("/auth/forgotpw", url.Values{"username": {"walter"}}, map[string]string{"Accept-Language": "nl"})

		if msgs := sink.all(); assert.Len(t, msgs, 1) {
			assert.Contains(t, msgs[0], TL("dutch", "email_template.password_reset_subject"))
			assert.Contains(t, msgs[0], "1 uur")
		}
	})

	t.Run("background email follows preferredlanguage", func(t *testing.T) {
		_, router, _ := newTestAppWith(t, func() {
			viper.Set("site.languages", []string{"english", "dutch"})
		})
		sink := newFakeSMTP(t)

		assert.NoError(t, router.emailer.SendPasswordExpiryReminderEmail(&ipa.User{
			Username: "walter", Email: "walter@example.com", PreferredLanguage: "nl-NL,en;q=0.5",
		}, 3))
		assert.NoError(t, router.emailer.SendPasswordExpiryReminderEmail(&ipa.User{
			Username: "jesse", Email: "jesse@example.com", PreferredLanguage: "fr",
		}, 3))

		if msgs := sink.all(); assert.Len(t, msgs, 2) {
			assert.Contains(t, msgs[0], TL("dutch", "email_template.password_expiry_subject"))
			assert.Contains(t, msgs[1], TL("english", "email_template.password_expiry_subject"))
		}
	})
}

func TestFormatDuration(t *testing.T) {
	defer viper.Reset()
	extraLanguages(t)
	assert.NoError(t, LoadTranslations())

	for d, want := range map[time.Duration]string{
		0:                    "0 seconds",
		time.Second:          "1 second",
		30 * time.Minute:     "30 minutes",
		time.Hour:            "1 hour",
		90 * time.Minute:     "1 hour",
		48 * time.Hour:       "2 days",
		14 * 24 * time.Hour:  "2 weeks",
		400 * 24 * time.Hour: "1 year",
	} {
		assert.Equal(t, want, formatDuration("english", d), d.String())
	}
	assert.Equal(t, "1 uur", formatDuration("dutch", time.Hour))
	assert.Equal(t, "3 dagen", formatDuration("dutch", 72*time.Hour))

	for n, want := range map[int]string{
		1: "1 минута", 2: "2 минуты", 5: "5 минут", 11: "11 минут",
		21: "21 минута", 22: "22 минуты", 25: "25 минут", 12: "12 минут", 14: "14 минут",
	} {
		assert.Equal(t, want, formatDuration("russian", time.Duration(n)*time.Minute), n)
	}
	assert.Equal(t, "1 hour", formatDuration("russian", time.Hour), "missing forms fall back to english")
	assert.Equal(t, "2 hours", formatDuration("russian", 2*time.Hour), "missing forms fall back to english")

	assert.Equal(t, "now", timeAgo("english", time.Now()))
	assert.Equal(t, "3 hours ago", timeAgo("english", time.Now().Add(-3*time.Hour)))
	assert.Equal(t, "2 days from now", timeAgo("english", time.Now().Add(49*time.Hour)))
	assert.Equal(t, "over 2 dagen", timeAgo("dutch", time.Now().Add(49*time.Hour)))
	assert.Equal(t, "5 минут назад", timeAgo("russian", time.Now().Add(-5*time.Minute)))
}
