// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	ipa "github.com/neverlless/goipa"
	"github.com/spf13/viper"
)

// Translation files are embedded in the binary. English and Dutch were
// contributed by @tubby1981 in upstream PR ubccr/mokey#157. Additional
// languages can be added via the site.translations_dir config option.

//go:embed translations
var translationFS embed.FS

var translations = make(map[string]map[string]string)

// languageCodes maps a language name to its BCP 47 tag, from
// builtinLanguageCodes or the file's top-level language_code.
var languageCodes = make(map[string]string)

var builtinLanguageCodes = map[string]string{
	"english":   "en",
	"dutch":     "nl",
	"russian":   "ru",
	"ukrainian": "uk",
}

// languages lists the names offered to visitors, default_language first.
var languages []string

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
		if key == "language_code" {
			continue
		}
		langTranslations[key] = v.GetString(key)
	}

	translations[lang] = langTranslations
	languageCodes[lang] = builtinLanguageCodes[lang]
	if code := v.GetString("language_code"); code != "" {
		languageCodes[lang] = strings.ToLower(code)
	}
	return nil
}

// LoadTranslations loads the embedded translation files and any additional
// .toml files from site.translations_dir. A file named <lang>.toml defines
// (or fully replaces) the language <lang>.
func LoadTranslations() error {
	translations = make(map[string]map[string]string)
	languageCodes = make(map[string]string)

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
			slog.Debug("Loaded translations", "lang", lang, "dir", dir)
		}
	}

	lang := defaultLanguage()
	if _, ok := translations[lang]; !ok {
		return fmt.Errorf("no translations found for configured default_language: %s", lang)
	}

	languages = []string{lang}
	for _, name := range viper.GetStringSlice("site.languages") {
		if _, ok := translations[name]; !ok {
			return fmt.Errorf("no translations found for language %s in site.languages", name)
		}
		if !slices.Contains(languages, name) {
			languages = append(languages, name)
		}
	}
	if len(languages) > 1 {
		for _, name := range languages {
			if languageCodes[name] == "" {
				return fmt.Errorf("language %s has no language_code, set one in its translation file", name)
			}
		}
	}

	slog.Info("Using languages", "languages", strings.Join(languages, ", "), "default", lang)
	return nil
}

func defaultLanguage() string {
	lang := viper.GetString("site.default_language")
	if lang == "" {
		lang = "english"
	}
	return lang
}

// TL returns the translation for key in lang, falling back to english and
// finally to the key itself.
func TL(lang, key string) string {
	key = strings.ToLower(key)

	if value, ok := translations[lang][key]; ok {
		return value
	}
	if value, ok := translations["english"][key]; ok {
		return value
	}

	slog.Warn("Missing translation", "key", key, "lang", lang)
	return key
}

// TC translates key into the language picked for the request.
func TC(c *fiber.Ctx, key string) string {
	return TL(requestLanguage(c), key)
}

func requestLanguage(c *fiber.Ctx) string {
	if lang, ok := c.Locals("lang").(string); ok && lang != "" {
		return lang
	}
	return defaultLanguage()
}

// userLanguage is the language for mail to user outside of a request: their
// FreeIPA preferredlanguage when offered, else default_language.
func userLanguage(user *ipa.User) string {
	if lang := matchLanguage(user.PreferredLanguage); lang != "" {
		return lang
	}
	return defaultLanguage()
}

// SetLanguage picks the request language from Accept-Language among
// site.languages.
func SetLanguage(c *fiber.Ctx) error {
	lang := defaultLanguage()
	if len(languages) > 1 {
		c.Vary(fiber.HeaderAcceptLanguage)
		if match := matchLanguage(c.Get(fiber.HeaderAcceptLanguage)); match != "" {
			lang = match
		}
	}
	c.Locals("lang", lang)
	return c.Next()
}

// matchLanguage returns the offered language that best fits an
// Accept-Language style list such as "ru-RU,ru;q=0.9,en;q=0.5", or "".
func matchLanguage(list string) string {
	best, bestQ := "", 0.0
	for _, item := range strings.Split(list, ",") {
		tag, params, _ := strings.Cut(item, ";")
		q := 1.0
		for _, param := range strings.Split(params, ";") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(param), "q="); ok {
				var err error
				if q, err = strconv.ParseFloat(v, 64); err != nil {
					q = 0
				}
			}
		}
		if !(q > bestQ) {
			continue
		}
		if lang := offeredLanguage(strings.ToLower(strings.TrimSpace(tag))); lang != "" {
			best, bestQ = lang, q
		}
	}
	return best
}

// offeredLanguage matches tag exactly, then by its primary subtag (ru-RU → ru).
func offeredLanguage(tag string) string {
	primary, _, _ := strings.Cut(tag, "-")
	for _, want := range []string{tag, primary} {
		for _, lang := range languages {
			if languageCodes[lang] == want {
				return lang
			}
		}
	}
	return ""
}
