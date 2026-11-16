package server

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type faApp struct {
	Host        string   `mapstructure:"host"`
	Name        string   `mapstructure:"name"`
	Groups      []string `mapstructure:"groups"`
	HBACService string   `mapstructure:"hbac_service"`
	HBACHost    string   `mapstructure:"hbac_host"`
}

type forwardAuthConfig struct {
	URL                              *url.URL
	SessionIdle, SessionMax, Recheck time.Duration
	Apps                             map[string]faApp
}

// App is nil-safe: a nil config is the disabled feature.
func (c *forwardAuthConfig) App(host string) (faApp, bool) {
	if c == nil {
		return faApp{}, false
	}
	a, ok := c.Apps[host]
	return a, ok
}

func faDuration(key string) (time.Duration, error) {
	d, err := time.ParseDuration(viper.GetString(key))
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: %q is not a positive duration such as \"8h\"", key, viper.GetString(key))
	}
	return d, nil
}

func loadForwardAuthConfig() (*forwardAuthConfig, error) {
	if !viper.GetBool("forward_auth.enabled") {
		return nil, nil
	}
	u, err := url.Parse(viper.GetString("forward_auth.url"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("forward_auth.url: an https URL is required, e.g. https://id.example.com")
	}
	c := &forwardAuthConfig{URL: u, Apps: map[string]faApp{}}
	if c.SessionIdle, err = faDuration("forward_auth.session_idle"); err != nil {
		return nil, err
	}
	if c.SessionMax, err = faDuration("forward_auth.session_max"); err != nil {
		return nil, err
	}
	if c.Recheck, err = faDuration("forward_auth.recheck"); err != nil {
		return nil, err
	}

	mokeyHosts := []string{strings.ToLower(u.Host)}
	if b, err := url.Parse(viper.GetString("email.base_url")); err == nil && b.Host != "" {
		mokeyHosts = append(mokeyHosts, strings.ToLower(b.Host))
	}

	var apps []faApp
	if err := viper.UnmarshalKey("forward_auth.apps", &apps); err != nil {
		return nil, fmt.Errorf("forward_auth.apps: %w", err)
	}
	if len(apps) == 0 {
		return nil, fmt.Errorf("forward_auth.apps: at least one [[forward_auth.apps]] is required when forward_auth.enabled is true")
	}
	for _, a := range apps {
		switch {
		case a.Host == "" || strings.ContainsAny(a.Host, ":/@?#\\ \t"):
			return nil, fmt.Errorf("forward_auth.apps: host %q must be a bare host name without scheme, port or path", a.Host)
		case a.Host != strings.ToLower(a.Host):
			return nil, fmt.Errorf("forward_auth.apps: host %q must be lowercase", a.Host)
		case containsString(mokeyHosts, a.Host):
			return nil, fmt.Errorf("forward_auth.apps: host %q is mokey's own host", a.Host)
		}
		if _, dup := c.Apps[a.Host]; dup {
			return nil, fmt.Errorf("forward_auth.apps: duplicate host %q", a.Host)
		}
		if a.HBACHost == "" {
			a.HBACHost = a.Host
		}
		c.Apps[a.Host] = a
	}
	return c, nil
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
