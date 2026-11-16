package server

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func faApps(hosts ...string) []any {
	var out []any
	for _, h := range hosts {
		out = append(out, map[string]any{"host": h, "name": "App"})
	}
	return out
}

func TestLoadForwardAuthConfigErrors(t *testing.T) {
	cases := []struct {
		name, want string
		set        map[string]any
	}{
		{"no url", "forward_auth.url", map[string]any{"forward_auth.apps": faApps("a.example.com")}},
		{"http url", "https", map[string]any{"forward_auth.url": "http://id.example.com", "forward_auth.apps": faApps("a.example.com")}},
		{"no apps", "forward_auth.apps", map[string]any{"forward_auth.url": "https://id.example.com"}},
		{"empty host", "host", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("")}},
		{"scheme", "host", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("https://a.example.com")}},
		{"port", "host", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("a.example.com:8443")}},
		{"path", "host", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("a.example.com/x")}},
		{"upper", "lowercase", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("A.example.com")}},
		{"duplicate", "duplicate", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("a.example.com", "a.example.com")}},
		{"mokey host", "mokey", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("id.example.com")}},
		{"bad idle", "session_idle", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("a.example.com"), "forward_auth.session_idle": "soon"}},
		{"bad max", "session_max", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("a.example.com"), "forward_auth.session_max": "-1h"}},
		{"bad recheck", "recheck", map[string]any{"forward_auth.url": "https://id.example.com", "forward_auth.apps": faApps("a.example.com"), "forward_auth.recheck": "0s"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			SetDefaults()
			viper.Set("forward_auth.enabled", true)
			for k, v := range tc.set {
				viper.Set(k, v)
			}
			c, err := loadForwardAuthConfig()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want containing %q", err, tc.want)
			}
			if c != nil {
				t.Fatal("expected nil config")
			}
		})
	}
}

func TestLoadForwardAuthConfig(t *testing.T) {
	viper.Reset()
	SetDefaults()
	if c, err := loadForwardAuthConfig(); c != nil || err != nil {
		t.Fatalf("disabled: %v, %v", c, err)
	}
	if _, ok := (*forwardAuthConfig)(nil).App("x"); ok {
		t.Fatal("nil config must have no apps")
	}

	viper.Set("forward_auth.enabled", true)
	viper.Set("forward_auth.url", "https://id.example.com")
	viper.Set("forward_auth.apps", []any{
		map[string]any{"host": "kubecost.example.com", "name": "Kubecost", "groups": []string{"finops"}, "hbac_service": "kubecost"},
		map[string]any{"host": "wiki.example.com", "hbac_host": "wiki-int.example.com"},
	})
	c, err := loadForwardAuthConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.URL.Host != "id.example.com" || c.SessionIdle != 8*time.Hour || c.SessionMax != 24*time.Hour || c.Recheck != 2*time.Minute {
		t.Fatalf("defaults: %+v", c)
	}
	a, ok := c.App("kubecost.example.com")
	if !ok || a.Name != "Kubecost" || a.HBACHost != "kubecost.example.com" || a.HBACService != "kubecost" || len(a.Groups) != 1 {
		t.Fatalf("app: %+v", a)
	}
	if a, _ := c.App("wiki.example.com"); a.HBACHost != "wiki-int.example.com" {
		t.Fatalf("hbac_host: %+v", a)
	}
	if _, ok := c.App("other.example.com"); ok {
		t.Fatal("unknown host matched")
	}
}
