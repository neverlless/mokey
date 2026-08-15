// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Translation files are embedded in the binary. English and Dutch were
// contributed by @tubby1981 in upstream PR ubccr/mokey#157. Additional
// languages can be added via the site.translations_dir config option.

//go:embed translations
var translationFS embed.FS

var translations = make(map[string]map[string]string)

func parseTranslationFile(lang string, path string, in fs.FS) error {
	v := viper.New()
	v.SetConfigType("toml")

	var err error
	if in != nil {
		f, ferr := in.Open(path)
		if ferr != nil {
			return ferr
		}
		defer f.Close()
		err = v.ReadConfig(f)
	} else {
		v.SetConfigFile(path)
		err = v.ReadInConfig()
	}
	if err != nil {
		return fmt.Errorf("failed to parse translation file %s: %w", path, err)
	}

	langTranslations := make(map[string]string)
	for _, key := range v.AllKeys() {
		langTranslations[key] = v.GetString(key)
	}

	translations[lang] = langTranslations
	return nil
}

// LoadTranslations loads the embedded translation files and any additional
// .toml files from site.translations_dir. A file named <lang>.toml defines
// (or fully replaces) the language <lang>.
func LoadTranslations() error {
	translations = make(map[string]map[string]string)

	entries, err := translationFS.ReadDir("translations")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		lang := strings.TrimSuffix(entry.Name(), ".toml")
		if err := parseTranslationFile(lang, filepath.Join("translations", entry.Name()), translationFS); err != nil {
			return err
		}
	}

	dir := viper.GetString("site.translations_dir")
	if dir != "" {
		files, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("failed to read translations_dir: %w", err)
		}

		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".toml") {
				continue
			}
			lang := strings.TrimSuffix(file.Name(), ".toml")
			if err := parseTranslationFile(lang, filepath.Join(dir, file.Name()), nil); err != nil {
				return err
			}
			log.Debugf("Loaded translations for language %s from %s", lang, dir)
		}
	}

	lang := defaultLanguage()
	if _, ok := translations[lang]; !ok {
		return fmt.Errorf("no translations found for configured default_language: %s", lang)
	}

	log.Infof("Using language: %s", lang)
	return nil
}

func defaultLanguage() string {
	lang := viper.GetString("site.default_language")
	if lang == "" {
		lang = "english"
	}
	return lang
}

// T returns the translation for key in the configured site language, falling
// back to english and finally to the key itself.
func T(key string) string {
	key = strings.ToLower(key)

	lang := defaultLanguage()
	if langTranslations, ok := translations[lang]; ok {
		if value, ok := langTranslations[key]; ok {
			return value
		}
	}

	if lang != "english" {
		if englishTranslations, ok := translations["english"]; ok {
			if value, ok := englishTranslations[key]; ok {
				return value
			}
		}
	}

	log.Warnf("Missing translation for key '%s' in language '%s'", key, lang)
	return key
}
