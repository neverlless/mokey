package server

import (
	"fmt"
	"slices"
	"time"

	"github.com/spf13/viper"
)

type lifecycleConfig struct {
	Reminders     []int // days before expiry, largest first
	Renewal       time.Duration
	AssignMissing bool
	MaxChanges    int
}

// loadLifecycleConfig returns nil when no lifecycle option is on.
func loadLifecycleConfig() (*lifecycleConfig, error) {
	c := &lifecycleConfig{
		Reminders:     viper.GetIntSlice("lifecycle.expiry_reminders"),
		AssignMissing: viper.GetBool("lifecycle.assign_missing_expiry"),
		MaxChanges:    viper.GetInt("lifecycle.max_changes_per_run"),
	}
	for _, d := range c.Reminders {
		if d < 1 {
			return nil, fmt.Errorf("lifecycle.expiry_reminders: %d is not a positive number of days", d)
		}
	}
	slices.SortFunc(c.Reminders, func(a, b int) int { return b - a })
	c.Reminders = slices.Compact(c.Reminders)

	if s := viper.GetString("lifecycle.renewal_period"); s != "" {
		d, err := parseGroupDuration(s)
		if err != nil {
			return nil, fmt.Errorf("lifecycle.renewal_period: %w", err)
		}
		c.Renewal = d
	}
	if c.AssignMissing && c.Renewal == 0 {
		return nil, fmt.Errorf("lifecycle.renewal_period: required by lifecycle.assign_missing_expiry")
	}
	if c.MaxChanges < 1 {
		return nil, fmt.Errorf("lifecycle.max_changes_per_run: %d must be at least 1", c.MaxChanges)
	}
	if len(c.Reminders) == 0 && c.Renewal == 0 {
		return nil, nil
	}
	return c, nil
}

// on is nil-safe: a nil config is the disabled feature.
func (c *lifecycleConfig) on() bool { return c != nil }
