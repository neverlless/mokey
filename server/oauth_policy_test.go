package server

import (
	"encoding/json"
	"testing"

	ipa "github.com/neverlless/goipa"
	hydra "github.com/ory/hydra-client-go/v26"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hydraClient decodes a client the way hydra-client-go does, so Metadata
// has the shape mokey sees from Hydra
func hydraClient(t *testing.T, js string) *hydra.OAuth2Client {
	t.Helper()
	var cl hydra.OAuth2Client
	require.NoError(t, json.Unmarshal([]byte(js), &cl))
	return &cl
}

func TestResolveClientPolicy(t *testing.T) {
	tests := []struct {
		name        string
		client      string
		defaultDeny bool
		want        clientPolicy
	}{
		{"config wins over metadata", `{"client_id":"grafana","metadata":{"mokey":{"access":"all"}}}`, false,
			clientPolicy{Source: "config", Groups: []string{"grafana-users"}}},
		{"metadata groups", `{"client_id":"wiki","metadata":{"mokey":{"access":"groups","groups":["staff"]}}}`, false,
			clientPolicy{Source: "metadata", Groups: []string{"staff"}}},
		{"metadata all beats default_deny", `{"client_id":"wiki","metadata":{"mokey":{"access":"all"}}}`, true,
			clientPolicy{Source: "metadata", All: true}},
		{"no metadata, default_deny", `{"client_id":"wiki","metadata":{"other":1}}`, true,
			clientPolicy{Source: "default"}},
		{"no metadata, no deny", `{"client_id":"wiki"}`, false,
			clientPolicy{Source: "default", All: true}},
		{"invalid metadata denies", `{"client_id":"wiki","metadata":{"mokey":{"access":"everyone"}}}`, false,
			clientPolicy{Source: "metadata"}},
		{"malformed metadata denies", `{"client_id":"wiki","metadata":{"mokey":"all"}}`, false,
			clientPolicy{Source: "metadata"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			viper.Set("hydra.clients", []map[string]any{{"client_id": "grafana", "groups": []string{"grafana-users"}}})
			viper.Set("hydra.default_deny", tt.defaultDeny)
			assert.Equal(t, tt.want, resolveClientPolicy(hydraClient(t, tt.client)))
		})
	}
}

func TestConfigClientPolicyInvalidDenies(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	for name, v := range map[string]any{
		"not a list":      "grafana",
		"empty client_id": []map[string]any{{"groups": []string{"x"}}},
	} {
		viper.Set("hydra.clients", v)
		p, ok := configClientPolicy("wiki")
		assert.True(t, ok, name)
		assert.False(t, p.All, name)
		assert.Empty(t, p.Groups, name)
		assert.False(t, policyAllows(resolveClientPolicy(hydraClient(t, `{"client_id":"wiki","metadata":{"mokey":{"access":"all"}}}`)), &ipa.User{}), name)
	}
}

func TestPolicyAllowsCaseAndNested(t *testing.T) {
	user := &ipa.User{Groups: []string{"ipausers"}, IndirectGroups: []string{"Staff"}}
	assert.True(t, policyAllows(clientPolicy{Groups: []string{"staff"}}, user))
	assert.False(t, policyAllows(clientPolicy{Groups: []string{"ops"}}, user))
	assert.False(t, policyAllows(clientPolicy{}, user))
	assert.True(t, policyAllows(clientPolicy{All: true}, user))
}

func TestWriteClientMetaKeepsOtherKeys(t *testing.T) {
	cl := hydraClient(t, `{"client_id":"wiki","metadata":{"owner":"it","mokey":{"access":"all"}}}`)
	no := false
	writeClientMeta(cl, clientMeta{Access: "groups", Groups: []string{"staff"}, Catalog: &no})

	b, err := json.Marshal(cl.Metadata)
	require.NoError(t, err)
	assert.JSONEq(t, `{"owner":"it","mokey":{"access":"groups","groups":["staff"],"catalog":false}}`, string(b))

	m, err := readClientMeta(cl)
	require.NoError(t, err)
	assert.Equal(t, &clientMeta{Access: "groups", Groups: []string{"staff"}, Catalog: &no}, m)

	empty := &hydra.OAuth2Client{}
	writeClientMeta(empty, clientMeta{Access: "all"})
	m, err = readClientMeta(empty)
	require.NoError(t, err)
	assert.Equal(t, &clientMeta{Access: "all"}, m)
}

func TestReadClientMetaAbsent(t *testing.T) {
	for _, js := range []string{`{}`, `{"metadata":null}`, `{"metadata":{"x":1}}`, `{"metadata":"free text"}`, `{"metadata":{"mokey":null}}`} {
		m, err := readClientMeta(hydraClient(t, js))
		assert.NoError(t, err, js)
		assert.Nil(t, m, js)
	}
}

func TestLoadHydraPublicURL(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	for in, want := range map[string]string{
		"":                           "",
		"https://auth.example.com/":  "https://auth.example.com",
		"https://example.com/hydra/": "https://example.com/hydra",
		"http://localhost:4444":      "http://localhost:4444",
		"http://127.0.0.1:4444/":     "http://127.0.0.1:4444",
		"http://[::1]:4444":          "http://[::1]:4444",
	} {
		viper.Set("hydra.public_url", in)
		got, err := loadHydraPublicURL()
		assert.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"http://auth.example.com", "auth.example.com", "ftp://auth.example.com", "https://", "https://u@auth.example.com", "https://auth.example.com?x=1", "https://auth.example.com#x"} {
		viper.Set("hydra.public_url", in)
		_, err := loadHydraPublicURL()
		assert.ErrorContains(t, err, "hydra.public_url", in)
	}
}
