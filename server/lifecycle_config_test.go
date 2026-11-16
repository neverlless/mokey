package server

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestLoadLifecycleConfig(t *testing.T) {
	load := func(set map[string]any) (*lifecycleConfig, error) {
		viper.Reset()
		SetDefaults()
		for k, v := range set {
			viper.Set(k, v)
		}
		return loadLifecycleConfig()
	}

	c, err := load(nil)
	if err != nil || c != nil || c.on() {
		t.Fatalf("defaults: %v, %v", c, err)
	}

	c, err = load(map[string]any{"lifecycle.expiry_reminders": []int{1, 30, 7, 7}})
	if err != nil || !c.on() || !slices.Equal(c.Reminders, []int{30, 7, 1}) || c.Renewal != 0 || c.MaxChanges != 50 {
		t.Fatalf("reminders: %+v, %v", c, err)
	}

	c, err = load(map[string]any{"lifecycle.renewal_period": "365d", "lifecycle.assign_missing_expiry": true, "lifecycle.max_changes_per_run": 5})
	if err != nil || c.Renewal != 8760*time.Hour || !c.AssignMissing || c.MaxChanges != 5 {
		t.Fatalf("renewal: %+v, %v", c, err)
	}

	for _, tc := range []struct {
		name, want string
		set        map[string]any
	}{
		{"bad duration", "lifecycle.renewal_period", map[string]any{"lifecycle.renewal_period": "1w"}},
		{"negative max", "lifecycle.max_changes_per_run", map[string]any{"lifecycle.renewal_period": "30d", "lifecycle.max_changes_per_run": -1}},
		{"bad reminder", "lifecycle.expiry_reminders", map[string]any{"lifecycle.expiry_reminders": []int{0}}},
		{"assign without period", "lifecycle.renewal_period", map[string]any{"lifecycle.assign_missing_expiry": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := load(tc.set)
			if err == nil || !strings.Contains(err.Error(), tc.want) || c != nil {
				t.Fatalf("err = %v, c = %v; want containing %q", err, c, tc.want)
			}
		})
	}
}
