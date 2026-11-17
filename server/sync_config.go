package server

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type googleSourceConfig struct {
	CredentialsFile, ServiceAccountEmail, AdminEmail, Customer, Query string
	OrgUnits, Domains                                                 []string
}

type syncConfig struct {
	Interval          time.Duration // 0 = no in-serve schedule
	ManagedGroup      string
	DefaultGroups     []string
	ExcludeUsers      []string
	Username          string // "local_part" | "email"
	AdoptExisting     bool
	MaxDisablePercent int // 0 = off
	MaxUsernameLength int
	Concurrency       int
	Disable           bool
	DeleteAfter       time.Duration // 0 = never
	Preserve          bool
	WelcomeMail       bool
	WelcomeLinkTTL    time.Duration
	MaxEventsPerRun   int
	ImportLegacyLocks bool
	Google            googleSourceConfig
	GroupMapping      map[string][]string // keys are lowercased Google group emails
}

// syncDuration reads an optional duration; with zeroOK "0" means 0.
func syncDuration(key string, zeroOK bool) (time.Duration, error) {
	s := viper.GetString(key)
	if s == "" || (zeroOK && s == "0") {
		return 0, nil
	}
	d, err := parseGroupDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// loadSyncConfig returns nil when sync.enabled is false.
func loadSyncConfig() (*syncConfig, error) {
	if !viper.GetBool("sync.enabled") {
		return nil, nil
	}
	c := &syncConfig{
		ManagedGroup:      syncName(viper.GetString("sync.managed_group")),
		DefaultGroups:     syncNames(viper.GetStringSlice("sync.default_groups")),
		ExcludeUsers:      syncNames(viper.GetStringSlice("sync.exclude_users")),
		Username:          viper.GetString("sync.username"),
		AdoptExisting:     viper.GetBool("sync.adopt_existing"),
		MaxDisablePercent: viper.GetInt("sync.max_disable_percent"),
		MaxUsernameLength: viper.GetInt("sync.max_username_length"),
		Concurrency:       viper.GetInt("sync.concurrency"),
		Disable:           viper.GetBool("sync.disable"),
		Preserve:          viper.GetBool("sync.preserve"),
		WelcomeMail:       viper.GetBool("sync.welcome_mail"),
		MaxEventsPerRun:   viper.GetInt("sync.max_events_per_run"),
		ImportLegacyLocks: viper.GetBool("sync.import_google2ipa_locks"),
		Google: googleSourceConfig{
			CredentialsFile:     viper.GetString("sync.google.credentials_file"),
			ServiceAccountEmail: viper.GetString("sync.google.service_account_email"),
			AdminEmail:          viper.GetString("sync.google.admin_email"),
			Customer:            viper.GetString("sync.google.customer"),
			Query:               viper.GetString("sync.google.query"),
			OrgUnits:            viper.GetStringSlice("sync.google.org_units"),
		},
		GroupMapping: map[string][]string{},
	}
	for _, d := range viper.GetStringSlice("sync.google.domains") {
		c.Google.Domains = append(c.Google.Domains, syncName(d))
	}

	var err error
	if c.Interval, err = syncDuration("sync.interval", false); err != nil {
		return nil, err
	}
	if c.DeleteAfter, err = syncDuration("sync.delete_after", true); err != nil {
		return nil, err
	}
	if c.WelcomeLinkTTL, err = syncDuration("sync.welcome_link_ttl", false); err != nil {
		return nil, err
	}

	if c.WelcomeLinkTTL <= 0 {
		return nil, fmt.Errorf("sync.welcome_link_ttl: must be a positive duration")
	}
	if c.WelcomeMail && viper.GetString("email.base_url") == "" {
		return nil, fmt.Errorf("sync.welcome_mail: requires email.base_url")
	}

	if c.Google.AdminEmail == "" {
		return nil, fmt.Errorf("sync.google.admin_email: required when sync.enabled is true")
	}
	if c.Username != "local_part" && c.Username != "email" {
		return nil, fmt.Errorf(`sync.username: %q must be "local_part" or "email"`, c.Username)
	}
	if c.MaxDisablePercent < 0 || c.MaxDisablePercent > 100 {
		return nil, fmt.Errorf("sync.max_disable_percent: %d must be between 0 and 100", c.MaxDisablePercent)
	}
	if c.MaxUsernameLength < 1 {
		return nil, fmt.Errorf("sync.max_username_length: %d must be at least 1", c.MaxUsernameLength)
	}
	if c.Concurrency < 1 {
		return nil, fmt.Errorf("sync.concurrency: %d must be at least 1", c.Concurrency)
	}
	if c.MaxEventsPerRun < 1 {
		return nil, fmt.Errorf("sync.max_events_per_run: %d must be at least 1", c.MaxEventsPerRun)
	}
	if viper.GetString("storage.driver") == "memory" {
		return nil, fmt.Errorf("sync.enabled: directory sync needs sqlite3 or redis storage")
	}

	for k, groups := range viper.GetStringMapStringSlice("sync.google.group_mapping") {
		k, groups = syncName(k), syncNames(groups)
		if slices.Contains(groups, "") {
			return nil, fmt.Errorf("sync.google.group_mapping: %q lists an empty group name", k)
		}
		c.GroupMapping[k] = append(c.GroupMapping[k], groups...)
	}
	ge, err := loadGroupExpiryConfig()
	if err != nil {
		return nil, err
	}
	if ge != nil {
		for _, g := range c.mappedGroups() {
			if _, limited := ge.Rules[g]; limited {
				return nil, fmt.Errorf("sync.google.group_mapping: group %q has a time limit in groups.rules; sync-managed membership can't be time-bound", g)
			}
		}
	}
	return c, nil
}

// FreeIPA uids and group names are lowercase; the config may not be.
func syncName(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func syncNames(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = syncName(v)
	}
	return out
}

// on is nil-safe: a nil config is the disabled feature.
func (c *syncConfig) on() bool { return c != nil }

// mappedGroups returns the sorted, unique FreeIPA groups named in GroupMapping.
func (c *syncConfig) mappedGroups() []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, gs := range c.GroupMapping {
		out = append(out, gs...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
