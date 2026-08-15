package server

import (
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
