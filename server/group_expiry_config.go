package server

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// parseGroupDuration is time.ParseDuration plus "<n>d" for n days.
func parseGroupDuration(s string) (time.Duration, error) {
	var d time.Duration
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, err
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}

type groupRule struct {
	Group string
	Max   time.Duration
}

type groupExpiryConfig struct {
	Durations      []time.Duration
	AllowPermanent bool
	Reminders      []time.Duration
	Rules          map[string]groupRule
}

func parseDurationList(key string) ([]time.Duration, error) {
	var out []time.Duration
	for _, s := range viper.GetStringSlice(key) {
		d, err := parseGroupDuration(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		out = append(out, d)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// loadGroupExpiryConfig returns nil when time-bound membership is not
// configured.
func loadGroupExpiryConfig() (*groupExpiryConfig, error) {
	durations, err := parseDurationList("groups.durations")
	if err != nil {
		return nil, err
	}
	reminders, err := parseDurationList("groups.reminders")
	if err != nil {
		return nil, err
	}
	var raw []struct{ Group, Max string }
	if err := viper.UnmarshalKey("groups.rules", &raw); err != nil {
		return nil, fmt.Errorf("groups.rules: %w", err)
	}

	if len(durations) == 0 {
		if len(reminders) > 0 {
			return nil, fmt.Errorf("groups.reminders needs groups.durations")
		}
		if len(raw) > 0 {
			return nil, fmt.Errorf("groups.rules needs groups.durations")
		}
		return nil, nil
	}
	if viper.GetString("storage.driver") == "memory" {
		return nil, fmt.Errorf("groups.durations: time-bound membership needs sqlite3 or redis storage")
	}
	if !viper.IsSet("groups.reminders") {
		reminders = []time.Duration{7 * 24 * time.Hour, 24 * time.Hour}
	}

	c := &groupExpiryConfig{
		Durations:      durations,
		AllowPermanent: viper.GetBool("groups.allow_permanent"),
		Reminders:      reminders,
		Rules:          map[string]groupRule{},
	}
	for _, rr := range raw {
		if rr.Group == "" {
			return nil, fmt.Errorf("groups.rules: group is required")
		}
		if _, dup := c.Rules[rr.Group]; dup {
			return nil, fmt.Errorf("groups.rules: duplicate rule for group %q", rr.Group)
		}
		max, err := parseGroupDuration(rr.Max)
		if err != nil {
			return nil, fmt.Errorf("groups.rules: group %q max: %w", rr.Group, err)
		}
		if durations[0] > max {
			return nil, fmt.Errorf("groups.rules: group %q max %s is below every groups.durations entry", rr.Group, rr.Max)
		}
		c.Rules[rr.Group] = groupRule{Group: rr.Group, Max: max}
	}
	return c, nil
}

// Methods accept a nil receiver: nil means the feature is off.

func (c *groupExpiryConfig) Enabled() bool { return c != nil }

// Offered returns the durations a member can pick for group and whether
// "no end date" is offered too.
func (c *groupExpiryConfig) Offered(group string) (durations []time.Duration, permanent bool) {
	if c == nil {
		return nil, true
	}
	rule, ruled := c.Rules[group]
	for _, d := range c.Durations {
		if !ruled || d <= rule.Max {
			durations = append(durations, d)
		}
	}
	return durations, c.AllowPermanent && !ruled
}

// Allowed reports whether d may be chosen for group; d == 0 is permanent.
func (c *groupExpiryConfig) Allowed(group string, d time.Duration) bool {
	if c == nil {
		return d == 0
	}
	durations, permanent := c.Offered(group)
	if d == 0 {
		return permanent
	}
	return slices.Contains(durations, d)
}

// warnRedisEviction logs when Redis may evict keys on its own, which would
// silently drop membership expiry records.
func (r *Router) warnRedisEviction() {
	if r.lock == nil || r.lock.rdb == nil {
		return
	}
	res, err := r.lock.rdb.ConfigGet(context.Background(), "maxmemory-policy").Result()
	if err != nil {
		return
	}
	if policy := res["maxmemory-policy"]; strings.HasPrefix(policy, "allkeys") {
		slog.Error("Redis may evict time-bound membership records; use a noeviction or volatile-* maxmemory-policy",
			"maxmemory-policy", policy)
	}
}
