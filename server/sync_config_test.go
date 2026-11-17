package server

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func loadSync(set map[string]any) (*syncConfig, error) {
	viper.Reset()
	SetDefaults()
	for k, v := range set {
		viper.Set(k, v)
	}
	return loadSyncConfig()
}

func syncOn(extra map[string]any) map[string]any {
	m := map[string]any{
		"sync.enabled":            true,
		"sync.google.admin_email": "admin@example.org",
		"storage.driver":          "sqlite3",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestSyncConfigOffByDefault(t *testing.T) {
	c, err := loadSync(nil)
	if err != nil || c != nil || c.on() || c.mappedGroups() != nil {
		t.Fatalf("defaults: %v, %v", c, err)
	}
	c, err = loadSync(map[string]any{"sync.google.admin_email": "x@example.org"})
	if err != nil || c != nil {
		t.Fatalf("not enabled: %v, %v", c, err)
	}
}

func TestSyncConfigDefaults(t *testing.T) {
	c, err := loadSync(syncOn(nil))
	if err != nil || !c.on() {
		t.Fatalf("load: %+v, %v", c, err)
	}
	if c.Interval != time.Hour || c.ManagedGroup != "google2ipa-managed" || len(c.DefaultGroups) != 0 ||
		!slices.Equal(c.ExcludeUsers, []string{"admin"}) || c.Username != "local_part" || c.AdoptExisting ||
		c.MaxDisablePercent != 20 || c.MaxUsernameLength != 32 || c.Concurrency != 4 || !c.Disable ||
		c.DeleteAfter != 30*24*time.Hour || !c.Preserve || c.WelcomeMail || c.WelcomeLinkTTL != 7*24*time.Hour ||
		c.MaxEventsPerRun != 50 || c.ImportLegacyLocks {
		t.Fatalf("defaults: %+v", c)
	}
	if c.Google.Customer != "my_customer" || c.Google.AdminEmail != "admin@example.org" {
		t.Fatalf("google: %+v", c.Google)
	}
}

func TestSyncConfigValues(t *testing.T) {
	c, err := loadSync(syncOn(map[string]any{"sync.interval": "", "sync.delete_after": "0", "sync.username": "email"}))
	if err != nil || c.Interval != 0 || c.DeleteAfter != 0 || c.Username != "email" {
		t.Fatalf("values: %+v, %v", c, err)
	}
}

func TestSyncConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		set        map[string]any
	}{
		{"no admin email", "sync.google.admin_email", map[string]any{"sync.google.admin_email": ""}},
		{"bad username", "sync.username", map[string]any{"sync.username": "x"}},
		{"memory", "sqlite3 or redis", map[string]any{"storage.driver": "memory"}},
		{"bad interval", "sync.interval", map[string]any{"sync.interval": "1w"}},
		{"bad delete_after", "sync.delete_after", map[string]any{"sync.delete_after": "soon"}},
		{"bad ttl", "sync.welcome_link_ttl", map[string]any{"sync.welcome_link_ttl": "-1h"}},
		{"percent", "sync.max_disable_percent", map[string]any{"sync.max_disable_percent": 101}},
		{"concurrency", "sync.concurrency", map[string]any{"sync.concurrency": 0}},
		{"empty group", "devs@example.org", map[string]any{"sync.google.group_mapping": map[string]any{"devs@example.org": []string{"ops", ""}}}},
		{"time-limited group", `"ops"`, map[string]any{
			"groups.durations":          []string{"1d"},
			"groups.rules":              []any{map[string]any{"group": "ops", "max": "1d"}},
			"sync.google.group_mapping": map[string]any{"devs@example.org": []string{"ops"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := loadSync(syncOn(tc.set))
			if err == nil || !strings.Contains(err.Error(), tc.want) || c != nil {
				t.Fatalf("err = %v, c = %v; want containing %q", err, c, tc.want)
			}
		})
	}
}

func TestSyncConfigMappingFromTOML(t *testing.T) {
	viper.Reset()
	SetDefaults()
	viper.SetConfigType("toml")
	toml := "[sync]\nenabled = true\n[sync.google]\nadmin_email = \"a@example.com\"\n[sync.google.group_mapping]\n\"Devops@Example.com\" = [\"admins\"]\n"
	if err := viper.ReadConfig(strings.NewReader(toml)); err != nil {
		t.Fatal(err)
	}
	viper.Set("storage.driver", "sqlite3")
	c, err := loadSyncConfig()
	if err != nil || !slices.Equal(c.GroupMapping["devops@example.com"], []string{"admins"}) {
		t.Fatalf("mapping: %+v, %v", c, err)
	}
}

func TestSyncConfigLowercasesMappingKeys(t *testing.T) {
	c, err := loadSync(syncOn(map[string]any{
		"sync.google.group_mapping": map[string]any{
			"Devops@Example.org": []string{"admins", "ops"},
			"qa@example.org":     []string{"ops"},
		},
		"sync.google.domains": []string{"Example.ORG"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.GroupMapping["devops@example.org"], []string{"admins", "ops"}) || len(c.GroupMapping) != 2 {
		t.Fatalf("mapping: %v", c.GroupMapping)
	}
	if !slices.Equal(c.Google.Domains, []string{"example.org"}) {
		t.Fatalf("domains: %v", c.Google.Domains)
	}
	if got := c.mappedGroups(); !slices.Equal(got, []string{"admins", "ops"}) {
		t.Fatalf("mappedGroups: %v", got)
	}
}
