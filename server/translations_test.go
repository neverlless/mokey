package server

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLoadTranslations(t *testing.T) {
	assert := assert.New(t)
	defer viper.Reset()

	viper.Set("site.default_language", "")
	assert.NoError(LoadTranslations())
	assert.Contains(translations, "english")
	assert.Contains(translations, "dutch")

	assert.Equal("Username", T("common.username"))
	assert.Equal("Password", T("common.password"))

	viper.Set("site.default_language", "dutch")
	assert.Equal("Gebruikersnaam", T("common.username"))

	// fall back to english for a key missing in the selected language
	viper.Set("site.default_language", "nosuchlang")
	err := LoadTranslations()
	assert.Error(err)
}

func TestTranslateFallback(t *testing.T) {
	assert := assert.New(t)
	defer viper.Reset()

	viper.Set("site.default_language", "")
	assert.NoError(LoadTranslations())

	// unknown key falls back to the key itself
	assert.Equal("no.such.key", T("no.such.key"))
}

// TestTranslationsComplete keeps every embedded language in step with
// english: the same keys, plural keys in the language's own forms, and the
// same printf verbs in each.
func TestTranslationsComplete(t *testing.T) {
	defer viper.Reset()
	assert.NoError(t, LoadTranslations())

	verbs := regexp.MustCompile(`%[-+# 0]*[0-9]*(\.[0-9]+)?[a-zA-Z%]`)
	plural := regexp.MustCompile(`^(duration\.\w+)_(one|other)$`)
	english := translations["english"]

	entries, err := translationFS.ReadDir("translations")
	assert.NoError(t, err)
	for _, entry := range entries {
		lang := strings.TrimSuffix(entry.Name(), ".toml")
		t.Run(lang, func(t *testing.T) {
			assert.NotEmpty(t, languageCodes[lang], "no language_code")

			// key -> the english key whose verbs it must carry
			want := make(map[string]string)
			for key := range english {
				if m := plural.FindStringSubmatch(key); m != nil {
					for n := range 200 {
						want[m[1]+"_"+pluralForm(lang, n)] = m[1] + "_other"
					}
					continue
				}
				want[key] = key
			}

			var missing, extra []string
			for key, ref := range want {
				value, ok := translations[lang][key]
				if !ok {
					missing = append(missing, key)
					continue
				}
				assert.Equal(t, verbs.FindAllString(english[ref], -1), verbs.FindAllString(value, -1), "printf verbs of %s", key)
			}
			for key := range translations[lang] {
				if _, ok := want[key]; !ok {
					extra = append(extra, key)
				}
			}
			slices.Sort(missing)
			slices.Sort(extra)
			assert.Empty(t, missing, "missing keys")
			assert.Empty(t, extra, "keys english does not have")
		})
	}
}
