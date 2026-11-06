package server

import (
	"embed"
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

//go:embed templates
var templateFiles embed.FS

// Template functions
var funcMap = template.FuncMap{
	"SplitSSHFP":             SplitSSHFP,
	"ConfigValueString":      ConfigValueString,
	"ConfigValueBool":        ConfigValueBool,
	"ConfigValueStringSlice": ConfigValueStringSlice,
	"AllowedDomains":         AllowedDomains,
	"BreakNewlines":          BreakNewlines,
	"PhoneCode":              PhoneCode,
	"PhoneNumber":            PhoneNumber,
	"PhoneCountries":         PhoneCountries,
	"PhoneFlag":              PhoneFlag,
	"Neg":                    func(n int) int { return -n },
}

// languageFuncs binds the language-dependent template functions to lang.
func languageFuncs(lang string) template.FuncMap {
	return template.FuncMap{
		"T":            func(key string) string { return TL(lang, key) },
		"TimeAgo":      func(t time.Time) string { return timeAgo(lang, t) },
		"LanguageCode": func() string { return languageCodes[lang] },
	}
}

type TemplateRenderer struct {
	templates *template.Template
	byLang    map[string]*template.Template
}

func NewTemplateRenderer() (*TemplateRenderer, error) {

	tmpl := template.New("")
	tmpl.Funcs(funcMap).Funcs(languageFuncs(defaultLanguage()))
	tmpl, err := tmpl.ParseFS(templateFiles, "templates/*.html", "templates/partials/*.html")
	if err != nil {
		return nil, err
	}

	if viper.IsSet("site.templates_dir") {
		localTemplatePath := filepath.Join(viper.GetString("site.templates_dir"), "*.html")
		localTemplates, err := filepath.Glob(localTemplatePath)
		if err != nil {
			return nil, err
		}

		if len(localTemplates) > 0 {
			tmpl, err = tmpl.ParseGlob(localTemplatePath)
			if err != nil {
				return nil, err
			}
		}
	}

	t := &TemplateRenderer{
		templates: tmpl,
		byLang:    make(map[string]*template.Template),
	}
	for _, lang := range languages {
		clone, err := tmpl.Clone()
		if err != nil {
			return nil, err
		}
		t.byLang[lang] = clone.Funcs(languageFuncs(lang))
	}

	return t, nil
}

func (t *TemplateRenderer) Load() error {
	return nil
}

// Render executes name in the template set of the language SetLanguage
// stored in the locals.
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, layouts ...string) error {
	tmpl := t.templates
	if m, ok := data.(fiber.Map); ok {
		if lang, ok := m["lang"].(string); ok && t.byLang[lang] != nil {
			tmpl = t.byLang[lang]
		}
	}
	return tmpl.ExecuteTemplate(w, name, data)
}

func AllowedDomains() string {
	allowedDomains := viper.GetStringMapString("accounts.allowed_domains")

	i := 0
	domains := make([]string, len(allowedDomains))
	for d := range allowedDomains {
		domains[i] = d
		i++
	}

	sort.Strings(domains)

	return strings.Join(domains, ", ")
}

func ConfigValueString(key string) string {
	return viper.GetString(key)
}

func ConfigValueBool(key string) bool {
	return viper.GetBool(key)
}

func ConfigValueStringSlice(key string) []string {
	return viper.GetStringSlice(key)
}

func SplitSSHFP(fp string) []string {
	if fp == "" {
		return []string{"", "", ""}
	}

	parts := strings.Split(fp, " ")
	if len(parts) == 1 {
		return []string{parts[0], "", ""}
	}

	if len(parts) == 2 {
		return []string{parts[0], parts[1], ""}
	}

	parts[2] = strings.TrimLeft(parts[2], "(")
	parts[2] = strings.TrimRight(parts[2], ")")
	return parts
}

func BreakNewlines(s string) template.HTML {
	// #nosec G203 -- input is HTML-escaped before the <br/> tags are inserted
	return template.HTML(strings.Replace(template.HTMLEscapeString(s), "\n", "<br />", -1))
}
