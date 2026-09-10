package server

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// TestUIPreviewServe boots the real app against the fake FreeIPA on a
// local port for visual work (screenshots, theme checks). Skipped unless
// MOKEY_UI_PREVIEW is set:
//
//	MOKEY_UI_PREVIEW=127.0.0.1:8899 go test ./server/ -run TestUIPreviewServe -count=1
//
// Log in as walter / Secret123!
func TestUIPreviewServe(t *testing.T) {
	addr := os.Getenv("MOKEY_UI_PREVIEW")
	if addr == "" {
		t.Skip("set MOKEY_UI_PREVIEW=host:port to serve the UI preview")
	}

	app, router, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_subid", true)
		viper.Set("admin.enabled", true)
	})

	fake.addUser("walter", &fakeUser{
		Password: "Secret123!",
		First:    "Walter", Last: "White",
		Email:  "wwhite@acme.local",
		Groups: []string{"ipausers", "chemists", "lab-admins", "admins"},
	})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{Description: "Lab crew", ManagerUsers: []string{"walter"}, Members: []string{"walter"}})
	fake.addGroup("glee-club", &fakeGroup{Description: "After-hours choir", ManagerUsers: []string{"jesse"}})
	fake.subids["walter"] = &fakeSubid{SubUID: 2147483648, SubGID: 2147483648}
	fake.addHBACRule("lab-access", &fakeHBACRule{
		Enabled: true, Description: "Lab SSH",
		MemberGroups: []string{"chemists"}, MemberHosts: []string{"lab.acme.local"}, MemberServices: []string{"sshd"},
	})
	fake.addSudoRule("lab-sudo", &fakeSudoRule{
		Enabled: true, MemberGroups: []string{"chemists"},
		HostCategory: "all", AllowCommands: []string{"/usr/bin/systemctl"},
	})
	router.addGroupRequest("chemists", "jesse", groupRequestJoin)

	t.Logf("UI preview on http://%s (walter / Secret123!)", addr)
	if err := app.Listen(addr); err != nil {
		t.Fatal(err)
	}
}

// #24: the toggle used to sit in the top bar next to the logo, where users
// found it distracting; it belongs with the help icon in the footer
func TestThemeToggleLivesInTheFooter(t *testing.T) {
	header, err := os.ReadFile("templates/header.html")
	if err != nil {
		t.Fatalf("read header: %s", err)
	}
	footer, err := os.ReadFile("templates/footer.html")
	if err != nil {
		t.Fatalf("read footer: %s", err)
	}

	if strings.Contains(string(header), `id="theme-toggle"`) {
		t.Error("theme toggle is back in the top bar")
	}
	if !strings.Contains(string(footer), `id="theme-toggle"`) {
		t.Error("theme toggle is missing from the footer")
	}
}

// #34: Bootstrap badges never wrap (white-space: nowrap), so a status
// sentence inside one runs out of the card. Badges are for short labels;
// an icon + sentence is a status message and belongs in an .alert
func TestStatusMessagesAreNotBadges(t *testing.T) {
	pages, err := filepath.Glob("templates/*.html")
	if err != nil || len(pages) == 0 {
		t.Fatalf("glob templates: %v", err)
	}
	statusBadge := regexp.MustCompile(`class="badge[^"]*">\s*<i `)
	for _, p := range pages {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %s", p, err)
		}
		if statusBadge.Match(b) {
			t.Errorf("%s: status message rendered as a badge, use an alert", p)
		}
	}
}

// The dark theme lightens the accent for contrast against the dark surface,
// but the button label stayed Bootstrap's white: 2.9:1 on #6f96e8. Every
// accent-filled button state has to clear WCAG AA (4.5:1) in both themes
func TestPrimaryButtonContrast(t *testing.T) {
	b, err := os.ReadFile("templates/static/css/style.css")
	if err != nil {
		t.Fatalf("read style.css: %s", err)
	}
	css := string(b)

	block := func(selector string) string {
		start := strings.Index(css, selector+" {")
		if start < 0 {
			t.Fatalf("style.css has no %s block", selector)
		}
		return css[start : start+strings.Index(css[start:], "\n}")]
	}
	hexVar := regexp.MustCompile(`(--mokey-[a-z-]+):\s*(#[0-9a-fA-F]{6});`)
	tokens := func(selector string) map[string]string {
		m := map[string]string{}
		for _, kv := range hexVar.FindAllStringSubmatch(block(selector), -1) {
			m[kv[1]] = kv[2]
		}
		return m
	}
	light := tokens(":root")
	dark := tokens(`[data-bs-theme="dark"]`)
	for k, v := range light {
		if _, ok := dark[k]; !ok {
			dark[k] = v
		}
	}

	btn := block(".btn-primary")
	for _, theme := range []struct {
		name string
		vars map[string]string
	}{{"light", light}, {"dark", dark}} {
		for _, state := range []struct{ label, bg string }{
			{"--bs-btn-color", "--mokey-accent"},
			{"--bs-btn-hover-color", "--mokey-accent-hover"},
			{"--bs-btn-active-color", "--mokey-accent-hover"},
		} {
			// Bootstrap's white unless the theme wires its own label color in
			fg := "#ffffff"
			if strings.Contains(btn, state.label+": var(--mokey-on-accent)") {
				fg = theme.vars["--mokey-on-accent"]
			}
			bg := theme.vars[state.bg]
			if fg == "" || bg == "" {
				t.Fatalf("%s theme: missing color for %s (fg %q, bg %q)", theme.name, state.label, fg, bg)
			}
			if r := contrastRatio(t, fg, bg); r < 4.5 {
				t.Errorf("%s theme: %s %s on %s is %.2f:1, below 4.5:1", theme.name, state.label, fg, bg, r)
			}
		}
	}
}

// WCAG 2.x relative-luminance contrast between two #rrggbb colors
func contrastRatio(t *testing.T, a, b string) float64 {
	lum := func(hex string) float64 {
		var r, g, bl uint8
		if _, err := fmt.Sscanf(strings.TrimPrefix(hex, "#"), "%02x%02x%02x", &r, &g, &bl); err != nil {
			t.Fatalf("parse color %q: %s", hex, err)
		}
		ch := func(v uint8) float64 {
			c := float64(v) / 255
			if c <= 0.03928 {
				return c / 12.92
			}
			return math.Pow((c+0.055)/1.055, 2.4)
		}
		return 0.2126*ch(r) + 0.7152*ch(g) + 0.0722*ch(bl)
	}
	hi, lo := lum(a), lum(b)
	if lo > hi {
		hi, lo = lo, hi
	}
	return (hi + 0.05) / (lo + 0.05)
}
