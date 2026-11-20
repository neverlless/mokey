package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	ipa "github.com/neverlless/goipa"
	hydra "github.com/ory/hydra-client-go/v26"
	"github.com/spf13/viper"
)

// hydraClientPolicy limits one OAuth client to members of FreeIPA groups,
// configured as [[hydra.clients]] entries.
type hydraClientPolicy struct {
	ClientID string   `mapstructure:"client_id"`
	Groups   []string `mapstructure:"groups"`
}

// clientMeta is who may sign in to a client, kept in its Hydra metadata
// under "mokey".
type clientMeta struct {
	Access  string   `json:"access,omitempty"` // "all" | "groups" | "" = not set
	Groups  []string `json:"groups,omitempty"`
	Catalog *bool    `json:"catalog,omitempty"` // nil = true
}

// clientPolicy is the resolved access rule for one client.
type clientPolicy struct {
	Source string   // "config" | "metadata" | "default"
	All    bool     // everyone may sign in
	Groups []string // when !All
}

// configPolicies parses [[hydra.clients]]; any invalid entry fails all.
func configPolicies() ([]hydraClientPolicy, error) {
	var policies []hydraClientPolicy
	if err := viper.UnmarshalKey("hydra.clients", &policies); err != nil {
		return nil, err
	}
	for _, p := range policies {
		if p.ClientID == "" {
			return nil, errors.New("entry without client_id")
		}
	}
	return policies, nil
}

// configClientPolicy returns the [[hydra.clients]] rule for clientID. An
// invalid config is a deny rule for every client.
func configClientPolicy(clientID string) (clientPolicy, bool) {
	policies, err := configPolicies()
	if err != nil {
		slog.Error("Invalid hydra.clients config, denying OAuth client access",
			"err", err,
		)
		return clientPolicy{Source: "config"}, true
	}
	for _, p := range policies {
		if p.ClientID == clientID {
			return clientPolicy{Source: "config", Groups: p.Groups}, true
		}
	}
	return clientPolicy{}, false
}

// readClientMeta returns nil, nil when the client has no mokey metadata.
func readClientMeta(cl *hydra.OAuth2Client) (*clientMeta, error) {
	if cl == nil || cl.Metadata == nil {
		return nil, nil
	}
	b, err := json.Marshal(cl.Metadata)
	if err != nil {
		return nil, err
	}
	// metadata that isn't an object belongs to some other tool
	var md map[string]json.RawMessage
	if json.Unmarshal(b, &md) != nil {
		return nil, nil
	}
	raw, ok := md["mokey"]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	var m clientMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	// no access (catalog only) leaves access to config or default_deny
	if m.Access != "" && m.Access != "all" && m.Access != "groups" {
		return nil, fmt.Errorf("metadata.mokey.access: %q is neither \"all\" nor \"groups\"", m.Access)
	}
	return &m, nil
}

// writeClientMeta sets metadata.mokey and keeps the other metadata keys
// and unknown keys inside "mokey".
func writeClientMeta(cl *hydra.OAuth2Client, m clientMeta) {
	mergeClientMeta(cl, func(mk map[string]interface{}) {
		mk["access"] = m.Access
		delete(mk, "groups")
		if len(m.Groups) > 0 {
			mk["groups"] = m.Groups
		}
		delete(mk, "catalog")
		if m.Catalog != nil {
			mk["catalog"] = *m.Catalog
		}
	})
}

// mergeClientMeta lets set change the metadata.mokey object in place.
func mergeClientMeta(cl *hydra.OAuth2Client, set func(map[string]interface{})) {
	md := map[string]interface{}{}
	if b, err := json.Marshal(cl.Metadata); err == nil {
		if json.Unmarshal(b, &md) != nil || md == nil {
			md = map[string]interface{}{}
		}
	}
	mokey, _ := md["mokey"].(map[string]interface{})
	if mokey == nil {
		mokey = map[string]interface{}{}
	}
	set(mokey)
	md["mokey"] = mokey
	cl.Metadata = md
}

// resolveClientPolicy: a [[hydra.clients]] entry wins, then metadata.mokey,
// then hydra.default_deny.
func resolveClientPolicy(cl *hydra.OAuth2Client) clientPolicy {
	if p, ok := configClientPolicy(cl.GetClientId()); ok {
		return p
	}
	m, err := readClientMeta(cl)
	if err != nil {
		slog.Error("Invalid mokey metadata on Hydra client, denying OAuth client access",
			"client", cl.GetClientId(),
			"err", err,
		)
		return clientPolicy{Source: "metadata"}
	}
	if m != nil && m.Access != "" {
		return clientPolicy{Source: "metadata", All: m.Access == "all", Groups: m.Groups}
	}
	return clientPolicy{Source: "default", All: !viper.GetBool("hydra.default_deny")}
}

// policyAllows: group names compare case-insensitively, nested groups count.
func policyAllows(p clientPolicy, user *ipa.User) bool {
	if p.All {
		return true
	}
	for _, want := range p.Groups {
		for _, have := range memberOf(user) {
			if strings.EqualFold(want, have) {
				return true
			}
		}
	}
	return false
}

// loadHydraPublicURL validates hydra.public_url: https, or http on a
// loopback host; the trailing slash is trimmed.
func loadHydraPublicURL() (string, error) {
	s := strings.TrimRight(viper.GetString("hydra.public_url"), "/")
	if s == "" {
		return "", nil
	}
	u, err := url.Parse(s)
	bad := err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != ""
	if !bad {
		switch u.Scheme {
		case "https":
		case "http":
			h := u.Hostname()
			bad = h != "localhost" && h != "127.0.0.1" && h != "::1"
		default:
			bad = true
		}
	}
	if bad {
		return "", fmt.Errorf("hydra.public_url: %q must be an absolute https URL (http only for localhost), e.g. https://auth.example.com", s)
	}
	return s, nil
}
