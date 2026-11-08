package server

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestParseGroupDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"8h": 8 * time.Hour, "30d": 720 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := parseGroupDuration(in); err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"0h", "-1d", "x", "1w", "106752d", "213504d"} {
		if _, err := parseGroupDuration(in); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestLoadGroupExpiryConfig(t *testing.T) {
	rule := func(g, m string) map[string]any { return map[string]any{"group": g, "max": m} }
	errCases := []struct {
		name, want string
		set        map[string]any
	}{
		{"memory", "needs sqlite3 or redis storage", map[string]any{"groups.durations": []string{"1d"}}},
		{"bad duration", "groups.durations", map[string]any{"storage.driver": "sqlite3", "groups.durations": []string{"1w"}}},
		{"rule without group", "groups.rules", map[string]any{"storage.driver": "sqlite3", "groups.durations": []string{"1d"}, "groups.rules": []any{rule("", "1d")}}},
		{"duplicate rule", "duplicate", map[string]any{"storage.driver": "sqlite3", "groups.durations": []string{"1d"}, "groups.rules": []any{rule("a", "1d"), rule("a", "2d")}}},
		{"max below durations", "below", map[string]any{"storage.driver": "sqlite3", "groups.durations": []string{"1d"}, "groups.rules": []any{rule("a", "8h")}}},
		{"reminders without durations", "groups.reminders", map[string]any{"groups.reminders": []string{"1d"}}},
		{"rules without durations", "groups.rules", map[string]any{"groups.rules": []any{rule("a", "1d")}}},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			SetDefaults()
			for k, v := range tc.set {
				viper.Set(k, v)
			}
			c, err := loadGroupExpiryConfig()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want containing %q", err, tc.want)
			}
			if c != nil {
				t.Fatal("expected nil config")
			}
		})
	}

	setup := func(kv map[string]any) *groupExpiryConfig {
		t.Helper()
		viper.Reset()
		SetDefaults()
		viper.Set("storage.driver", "sqlite3")
		for k, v := range kv {
			viper.Set(k, v)
		}
		c, err := loadGroupExpiryConfig()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	viper.Reset()
	SetDefaults()
	if c, err := loadGroupExpiryConfig(); c != nil || err != nil {
		t.Fatalf("unset: %v, %v", c, err)
	}

	c := setup(map[string]any{"groups.durations": []string{"7d", "8h", "8h"}})
	if want := []time.Duration{8 * time.Hour, 7 * 24 * time.Hour}; !slices.Equal(c.Durations, want) {
		t.Errorf("durations = %v; want %v", c.Durations, want)
	}
	if want := []time.Duration{24 * time.Hour, 7 * 24 * time.Hour}; !slices.Equal(c.Reminders, want) {
		t.Errorf("default reminders = %v; want %v", c.Reminders, want)
	}

	c = setup(map[string]any{
		"groups.durations": []string{"8h", "1d"},
		"groups.rules":     []any{rule("prod-sudo", "8h")},
	})
	if d, p := c.Offered("prod-sudo"); !slices.Equal(d, []time.Duration{8 * time.Hour}) || p {
		t.Errorf("ruled Offered = %v, %v", d, p)
	}
	if d, p := c.Offered("other"); len(d) != 2 || !p {
		t.Errorf("unruled Offered = %v, %v", d, p)
	}
	if c.Allowed("prod-sudo", 0) || !c.Allowed("prod-sudo", 8*time.Hour) || c.Allowed("prod-sudo", 24*time.Hour) {
		t.Error("ruled Allowed wrong")
	}
	if !c.Allowed("other", 0) {
		t.Error("unruled permanent should be allowed")
	}

	c = setup(map[string]any{"groups.durations": []string{"1d"}, "groups.allow_permanent": false})
	if _, p := c.Offered("x"); p || c.Allowed("x", 0) {
		t.Error("allow_permanent=false should not offer permanent")
	}

	var off *groupExpiryConfig
	if off.Enabled() || !off.Allowed("x", 0) || off.Allowed("x", time.Hour) {
		t.Error("nil config wrong")
	}
	if d, p := off.Offered("x"); d != nil || !p {
		t.Errorf("nil Offered = %v, %v", d, p)
	}
}

func TestGroupExpiryWarning(t *testing.T) {
	viper.Reset()
	SetDefaults()
	on := &groupExpiryConfig{}
	if msg := groupExpiryWarning(on); msg != "" {
		t.Errorf("unexpected warning %q", msg)
	}
	viper.Set("accounts.enable_groups", false)
	msg := groupExpiryWarning(on)
	if !strings.Contains(msg, "groups.durations") || !strings.Contains(msg, "accounts.enable_groups") {
		t.Errorf("warning = %q", msg)
	}
	if groupExpiryWarning(nil) != "" {
		t.Error("nil config should not warn")
	}
}
