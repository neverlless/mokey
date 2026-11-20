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
	if c.Google.Customer != "my_customer" || c.Google.AdminEmail != "admin@example.org" || c.Google.Endpoint != "" {
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
		{"empty ttl", "sync.welcome_link_ttl", map[string]any{"sync.welcome_link_ttl": ""}},
		{"zero ttl", "sync.welcome_link_ttl", map[string]any{"sync.welcome_link_ttl": "0"}},
		{"welcome without base url", "sync.welcome_mail: requires email.base_url", map[string]any{"sync.welcome_mail": true}},
		{"percent", "sync.max_disable_percent", map[string]any{"sync.max_disable_percent": 101}},
		{"concurrency", "sync.concurrency", map[string]any{"sync.concurrency": 0}},
		{"empty group", "devs@example.org", map[string]any{"sync.google.group_mapping": map[string]any{"devs@example.org": []string{"ops", ""}}}},
		{"relative org unit", `sync.google.org_units: "research" must start with /`, map[string]any{"sync.google.org_units": []string{"/Staff", " research"}}},
		{"rule without name", "sync.google.rules: rule 1: name is required", map[string]any{"sync.google.rules": []any{
			map[string]any{"department": []string{"eng"}, "groups": []string{"ops"}}}}},
		{"duplicate rule name", `duplicate rule name "eng"`, map[string]any{"sync.google.rules": []any{
			map[string]any{"name": "eng", "department": []string{"eng"}, "groups": []string{"ops"}},
			map[string]any{"name": " Eng", "title": []string{"sre"}, "groups": []string{"ops"}}}}},
		{"rule without condition", `rule "eng": needs at least one of`, map[string]any{"sync.google.rules": []any{
			map[string]any{"name": "eng", "groups": []string{"ops"}}}}},
		{"rule empty value", `rule "eng": department lists an empty value`, map[string]any{"sync.google.rules": []any{
			map[string]any{"name": "eng", "department": []string{"eng", " "}, "groups": []string{"ops"}}}}},
		{"rule without groups", `rule "eng": groups is required`, map[string]any{"sync.google.rules": []any{
			map[string]any{"name": "eng", "department": []string{"eng"}}}}},
		{"rule empty group", `rule "eng": groups lists an empty group name`, map[string]any{"sync.google.rules": []any{
			map[string]any{"name": "eng", "department": []string{"eng"}, "groups": []string{"ops", ""}}}}},
		{"rule unknown attribute", "departmnet", map[string]any{"sync.google.rules": []any{
			map[string]any{"name": "eng", "departmnet": []string{"eng"}, "groups": []string{"ops"}}}}},
		{"rule relative org unit", `rule "eng": org_unit "research" must start with /`, map[string]any{"sync.google.rules": []any{
			map[string]any{"name": "eng", "org_unit": []string{"research"}, "groups": []string{"ops"}}}}},
		{"rule first empty value in fixed order", `rule "eng": org_unit lists an empty value`, map[string]any{"sync.google.rules": []any{
			map[string]any{"name": "eng", "org_unit": []string{""}, "department": []string{""}, "title": []string{""}, "cost_center": []string{""}, "email_domain": []string{""}, "groups": []string{"ops"}}}}},
		{"rule on managed group", `rule "eng": targets the managed group`, map[string]any{"sync.google.rules": []any{
			map[string]any{"name": "eng", "department": []string{"eng"}, "groups": []string{"Google2IPA-Managed"}}}}},
		{"rule time-limited group", `"ops"`, map[string]any{
			"groups.durations":  []string{"1d"},
			"groups.rules":      []any{map[string]any{"group": "ops", "max": "1d"}},
			"sync.google.rules": []any{map[string]any{"name": "eng", "department": []string{"eng"}, "groups": []string{"ops"}}},
		}},
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

func TestSyncConfigNormalizesNames(t *testing.T) {
	c, err := loadSync(syncOn(map[string]any{
		"sync.managed_group":        " Google2IPA-Managed ",
		"sync.default_groups":       []string{"Staff ", "staff"},
		"sync.exclude_users":        []string{" Admin"},
		"sync.google.group_mapping": map[string]any{" Dev@Example.org ": []string{"DevOps", " ops"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ManagedGroup != "google2ipa-managed" || !slices.Equal(c.DefaultGroups, []string{"staff", "staff"}) ||
		!slices.Equal(c.ExcludeUsers, []string{"admin"}) || !slices.Equal(c.GroupMapping["dev@example.org"], []string{"devops", "ops"}) {
		t.Fatalf("not normalized: %+v", c)
	}
	if _, err := loadSync(syncOn(map[string]any{"sync.google.group_mapping": map[string]any{"a@example.org": []string{" "}}})); err == nil {
		t.Fatal("a blank group name must be rejected")
	}
}

func TestSyncConfigRulesFromTOML(t *testing.T) {
	viper.Reset()
	SetDefaults()
	viper.SetConfigType("toml")
	toml := `[sync]
enabled = true
[sync.google]
admin_email = "a@example.com"
[sync.google.group_mapping]
"devops@example.com" = ["admins", "hpc-users"]
[[sync.google.rules]]
name = " Research-Cluster "
org_unit = ["/Research/"]
groups = ["HPC-Users"]
[[sync.google.rules]]
name = "engineering-sudo"
department = ["Engineering", " Platform"]
title = ["SRE"]
cost_center = ["CC-1"]
email_domain = ["Example.com"]
groups = ["eng-sudo"]
`
	if err := viper.ReadConfig(strings.NewReader(toml)); err != nil {
		t.Fatal(err)
	}
	viper.Set("storage.driver", "sqlite3")
	c, err := loadSyncConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 2 {
		t.Fatalf("rules = %+v", c.Rules)
	}
	r0, r1 := c.Rules[0], c.Rules[1]
	if r0.Name != "research-cluster" || !slices.Equal(r0.Groups, []string{"hpc-users"}) || len(r0.Conds) != 1 ||
		!slices.Equal(r0.Conds["org_unit"], []string{"/research/"}) {
		t.Fatalf("rule 0 = %+v", r0)
	}
	if r1.Name != "engineering-sudo" || !slices.Equal(r1.Conds["department"], []string{"engineering", "platform"}) ||
		!slices.Equal(r1.Conds["title"], []string{"sre"}) || !slices.Equal(r1.Conds["cost_center"], []string{"cc-1"}) ||
		!slices.Equal(r1.Conds["email_domain"], []string{"example.com"}) || len(r1.Conds) != 4 {
		t.Fatalf("rule 1 = %+v", r1)
	}
	if got := c.ownedGroups(); !slices.Equal(got, []string{"admins", "eng-sudo", "hpc-users"}) {
		t.Fatalf("ownedGroups = %v", got)
	}
	if got := c.mappedGroups(); !slices.Equal(got, []string{"admins", "hpc-users"}) {
		t.Fatalf("mappedGroups = %v", got)
	}
	if got := c.groups(); !slices.Equal(got, []string{"admins", "eng-sudo", "google2ipa-managed", "hpc-users"}) {
		t.Fatalf("groups = %v", got)
	}
}
