package server

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"

	"github.com/neverlless/goipa/ipatest"
	hydra "github.com/ory/hydra-client-go/v26"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newClientsTestApp(t *testing.T, configure func()) (*Router, *fakeHydra) {
	t.Helper()
	hy := newFakeHydra()
	t.Cleanup(hy.Close)
	_, router, fake := newTestAppWith(t, func() {
		viper.Set("hydra.admin_url", hy.srv.URL)
		if configure != nil {
			configure()
		}
	})
	fake.AddGroup("devs", ipatest.Group{})
	fake.AddGroup("ops", ipatest.Group{})
	return router, hy
}

func webInput() clientInput {
	return clientInput{
		Name:         "Wiki",
		URI:          "https://wiki.example.com",
		Kind:         kindWeb,
		RedirectURIs: []string{"https://wiki.example.com/oauth/cb"},
		Scopes:       []string{"openid", "profile"},
		Access:       "groups",
		Groups:       []string{"devs"},
		Catalog:      true,
	}
}

func TestClientKindOf(t *testing.T) {
	s := func(v string) *string { return &v }
	cases := []struct {
		cl   hydra.OAuth2Client
		want clientKind
	}{
		{hydra.OAuth2Client{TokenEndpointAuthMethod: s("client_secret_basic"), GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}}, kindWeb},
		{hydra.OAuth2Client{GrantTypes: []string{"authorization_code"}}, kindWeb},
		{hydra.OAuth2Client{}, kindWeb},
		{hydra.OAuth2Client{TokenEndpointAuthMethod: s("none"), GrantTypes: []string{"authorization_code", "refresh_token"}}, kindPublic},
		{hydra.OAuth2Client{TokenEndpointAuthMethod: s("client_secret_basic"), GrantTypes: []string{"client_credentials"}}, kindMachine},
		{hydra.OAuth2Client{TokenEndpointAuthMethod: s("client_secret_post"), GrantTypes: []string{"authorization_code"}}, kindOther},
		{hydra.OAuth2Client{GrantTypes: []string{"authorization_code", "implicit"}}, kindOther},
		{hydra.OAuth2Client{GrantTypes: []string{"authorization_code", "client_credentials"}}, kindOther},
		{hydra.OAuth2Client{ResponseTypes: []string{"id_token"}}, kindOther},
	}
	for i, c := range cases {
		assert.Equal(t, c.want, clientKindOf(&c.cl), "case %d", i)
	}
}

func TestClientInputValidate(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*clientInput)
		field string // "" = valid
	}{
		{"ok", func(*clientInput) {}, ""},
		{"http localhost", func(in *clientInput) { in.RedirectURIs = []string{"http://localhost:8080/cb"} }, ""},
		{"http loopback v4", func(in *clientInput) { in.RedirectURIs = []string{"http://127.0.0.1/cb"} }, ""},
		{"http loopback v6", func(in *clientInput) { in.RedirectURIs = []string{"http://[::1]:9000/cb"} }, ""},
		{"http remote", func(in *clientInput) { in.RedirectURIs = []string{"http://wiki.example.com/cb"} }, "redirect_uris"},
		{"fragment", func(in *clientInput) { in.RedirectURIs = []string{"https://wiki.example.com/cb#x"} }, "redirect_uris"},
		{"relative", func(in *clientInput) { in.RedirectURIs = []string{"/cb"} }, "redirect_uris"},
		{"empty redirects", func(in *clientInput) { in.RedirectURIs = nil }, "redirect_uris"},
		{"custom scheme web", func(in *clientInput) { in.RedirectURIs = []string{"com.example.app:/callback"} }, "redirect_uris"},
		{"custom scheme public", func(in *clientInput) {
			in.Kind = kindPublic
			in.RedirectURIs = []string{"com.example.app:/callback"}
		}, ""},
		{"javascript public", func(in *clientInput) {
			in.Kind = kindPublic
			in.RedirectURIs = []string{"javascript:alert(1)"}
		}, "redirect_uris"},
		{"post logout http remote", func(in *clientInput) { in.PostLogoutURIs = []string{"http://wiki.example.com/bye"} }, "post_logout_redirect_uris"},
		{"id charset", func(in *clientInput) { in.ID = "Wiki App" }, "id"},
		{"id ok", func(in *clientInput) { in.ID = "wiki-2.app_x" }, ""},
		{"id dots", func(in *clientInput) { in.ID = ".." }, "id"},
		{"id dot", func(in *clientInput) { in.ID = "." }, "id"},
		{"id leading dash", func(in *clientInput) { in.ID = "-x" }, "id"},
		{"id 64", func(in *clientInput) { in.ID = strings.Repeat("a", 64) }, ""},
		{"id 65", func(in *clientInput) { in.ID = strings.Repeat("a", 65) }, "id"},
		{"userinfo", func(in *clientInput) { in.RedirectURIs = []string{"https://user@wiki.example.com/cb"} }, "redirect_uris"},
		{"empty host", func(in *clientInput) { in.RedirectURIs = []string{"https://:443/cb"} }, "redirect_uris"},
		{"app link userinfo", func(in *clientInput) { in.URI = "https://u:p@wiki.example.com" }, "uri"},
		{"app link empty host", func(in *clientInput) { in.URI = "https://:443" }, "uri"},
		{"app link javascript", func(in *clientInput) { in.URI = "javascript:alert(1)" }, "uri"},
		{"scope with space", func(in *clientInput) { in.Scopes = []string{"openid", "a b"} }, "scopes"},
		{"bad access", func(in *clientInput) { in.Access = "some" }, "access"},
		{"groups empty", func(in *clientInput) { in.Groups = nil }, "groups"},
		{"bad kind", func(in *clientInput) { in.Kind = "spa" }, "kind"},
	}
	for _, c := range cases {
		in := webInput()
		c.edit(&in)
		errs := in.validate()
		if c.field == "" {
			assert.Empty(t, errs, c.name)
			continue
		}
		assert.Contains(t, errs, c.field, c.name)
		assert.NotEmpty(t, errs[c.field], c.name)
	}
}

func TestNewClientSecret(t *testing.T) {
	a, err := newClientSecret()
	require.NoError(t, err)
	b, _ := newClientSecret()
	assert.NotEqual(t, a, b)
	raw, err := base64.RawURLEncoding.DecodeString(a)
	require.NoError(t, err)
	assert.Len(t, raw, 32)
}

func TestCreateWebClient(t *testing.T) {
	assert := assert.New(t)
	r, hy := newClientsTestApp(t, nil)

	id, secret, err := r.createOAuthClient(webInput(), "admin")
	require.NoError(t, err)
	assert.Equal("generated-1", id)
	assert.NotEmpty(secret)

	cl := hy.storedClient(id)
	require.NotNil(t, cl)
	assert.Equal(secret, cl["client_secret"])
	assert.Equal("Wiki", cl["client_name"])
	assert.Equal("https://wiki.example.com", cl["client_uri"])
	assert.Equal("client_secret_basic", cl["token_endpoint_auth_method"])
	assert.Equal([]interface{}{"authorization_code", "refresh_token"}, cl["grant_types"])
	assert.Equal([]interface{}{"code"}, cl["response_types"])
	assert.Equal([]interface{}{"https://wiki.example.com/oauth/cb"}, cl["redirect_uris"])
	assert.Equal("openid profile", cl["scope"])
	assert.Equal(map[string]interface{}{"access": "groups", "groups": []interface{}{"devs"}, "catalog": true},
		cl["metadata"].(map[string]interface{})["mokey"])
}

func TestCreatePublicClient(t *testing.T) {
	assert := assert.New(t)
	r, hy := newClientsTestApp(t, nil)

	in := webInput()
	in.ID = "cli"
	in.Kind = kindPublic
	in.Scopes = []string{"email"}
	in.Access = "all"
	in.Groups = nil
	id, secret, err := r.createOAuthClient(in, "admin")
	require.NoError(t, err)
	assert.Equal("cli", id)
	assert.Empty(secret)

	cl := hy.storedClient("cli")
	assert.Equal("none", cl["token_endpoint_auth_method"])
	assert.NotContains(cl, "client_secret")
	assert.Equal("openid email", cl["scope"])
}

func TestCreateRejectsOtherKind(t *testing.T) {
	r, hy := newClientsTestApp(t, nil)
	in := webInput()
	in.Kind = kindOther
	_, _, err := r.createOAuthClient(in, "admin")
	var verr clientInputError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr, "kind")
	assert.Zero(t, hy.clientWrites)
}

func TestUpdateKeepsUnknownFields(t *testing.T) {
	assert := assert.New(t)
	r, hy := newClientsTestApp(t, nil)
	hy.seedClient(map[string]interface{}{
		"client_id":                  "legacy",
		"client_name":                "Legacy",
		"client_secret":              "legacy-secret-placeholder",
		"token_endpoint_auth_method": "client_secret_post",
		"grant_types":                []interface{}{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"response_types":             []interface{}{"code"},
		"redirect_uris":              []interface{}{"https://legacy.example.com/cb"},
		"allowed_cors_origins":       []interface{}{"https://legacy.example.com"},
		"jwks":                       map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": "AQAB-placeholder", "e": "AQAB"}}},
		"authorization_code_grant_access_token_lifespan": "1h0m0s",
		"skip_consent": true,
		"metadata":     map[string]interface{}{"owner": "team-a"},
	})

	in := webInput()
	in.Kind = "" // ignored on update
	in.Name = "Legacy 2"
	in.RedirectURIs = []string{"https://legacy.example.com/cb2"}
	require.NoError(t, r.updateOAuthClient("legacy", in, "admin"))

	cl := hy.storedClient("legacy")
	assert.Equal("Legacy 2", cl["client_name"])
	assert.Equal([]interface{}{"https://legacy.example.com/cb2"}, cl["redirect_uris"])
	assert.Equal("legacy-secret-placeholder", cl["client_secret"])
	assert.Equal("client_secret_post", cl["token_endpoint_auth_method"])
	assert.Equal([]interface{}{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"}, cl["grant_types"])
	assert.Equal([]interface{}{"https://legacy.example.com"}, cl["allowed_cors_origins"])
	assert.Equal("1h0m0s", cl["authorization_code_grant_access_token_lifespan"])
	assert.Equal(true, cl["skip_consent"])
	assert.Equal(map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": "AQAB-placeholder", "e": "AQAB"}}}, cl["jwks"])
	md := cl["metadata"].(map[string]interface{})
	assert.Equal("team-a", md["owner"])
	assert.Equal("groups", md["mokey"].(map[string]interface{})["access"])
}

func TestUpdateConfigClientAccess(t *testing.T) {
	assert := assert.New(t)
	r, hy := newClientsTestApp(t, func() {
		viper.Set("hydra.clients", []map[string]interface{}{{"client_id": "grafana", "groups": []string{"Ops"}}})
	})
	hy.seedClient(map[string]interface{}{"client_id": "grafana", "client_name": "Grafana", "redirect_uris": []interface{}{"https://g.example.com/cb"}})

	in := webInput()
	err := r.updateOAuthClient("grafana", in, "admin")
	assert.ErrorIs(err, errClientAccessInConfig)
	assert.Zero(hy.clientWrites)

	in.Access, in.Groups = "", nil
	in.Name = "Grafana 2"
	require.NoError(t, r.updateOAuthClient("grafana", in, "admin"))
	cl := hy.storedClient("grafana")
	assert.Equal("Grafana 2", cl["client_name"])
	assert.Equal(map[string]interface{}{"mokey": map[string]interface{}{"access": "groups", "groups": []interface{}{"Ops"}, "catalog": true}}, cl["metadata"])

	// the move path: once the entry is gone, the mirrored groups apply
	viper.Set("hydra.clients", nil)
	fetched, err := r.getManagedClient("grafana")
	require.NoError(t, err)
	assert.Equal(clientPolicy{Source: "metadata", Groups: []string{"Ops"}}, resolveClientPolicy(fetched))
}

func TestUpdateConfigClientCatalog(t *testing.T) {
	assert := assert.New(t)
	r, hy := newClientsTestApp(t, func() {
		viper.Set("hydra.clients", []map[string]interface{}{{"client_id": "grafana", "groups": []string{"ops"}}})
	})
	hy.seedClient(map[string]interface{}{
		"client_id": "grafana", "redirect_uris": []interface{}{"https://g.example.com/cb"},
		"metadata": map[string]interface{}{"owner": "team-a", "mokey": map[string]interface{}{"access": "groups", "groups": []interface{}{"devs"}}},
	})

	before, err := r.getManagedClient("grafana")
	require.NoError(t, err)
	assert.Equal(clientPolicy{Source: "config", Groups: []string{"ops"}}, resolveClientPolicy(before))

	in := webInput()
	in.Access, in.Groups, in.Catalog = "", nil, false
	require.NoError(t, r.updateOAuthClient("grafana", in, "admin"))
	assert.Equal(map[string]interface{}{
		"owner": "team-a",
		"mokey": map[string]interface{}{"access": "groups", "groups": []interface{}{"ops"}, "catalog": false},
	}, hy.storedClient("grafana")["metadata"])

	in.Catalog = true
	require.NoError(t, r.updateOAuthClient("grafana", in, "admin"))
	md := hy.storedClient("grafana")["metadata"].(map[string]interface{})
	assert.Equal(true, md["mokey"].(map[string]interface{})["catalog"])
	assert.Equal("groups", md["mokey"].(map[string]interface{})["access"])
}

func TestUpdateInvalidConfigKeepsAccess(t *testing.T) {
	r, hy := newClientsTestApp(t, func() {
		viper.Set("hydra.clients", []map[string]interface{}{{"groups": []string{"ops"}}})
	})
	hy.seedClient(map[string]interface{}{
		"client_id": "wiki", "redirect_uris": []interface{}{"https://w.example.com/cb"},
		"metadata": map[string]interface{}{"mokey": map[string]interface{}{"access": "all"}},
	})
	in := webInput()
	in.Access, in.Groups = "", nil
	require.NoError(t, r.updateOAuthClient("wiki", in, "admin"))
	assert.Equal(t, map[string]interface{}{"access": "all", "catalog": true}, hy.storedClient("wiki")["metadata"].(map[string]interface{})["mokey"])
}

func TestCatalogOnlyMetadata(t *testing.T) {
	assert := assert.New(t)
	newClientsTestApp(t, nil)
	cl := &hydra.OAuth2Client{Metadata: map[string]interface{}{"mokey": map[string]interface{}{"catalog": false}}}
	cl.SetClientId("wiki")

	m, err := readClientMeta(cl)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.False(*m.Catalog)
	assert.Equal(clientPolicy{Source: "default", All: true}, resolveClientPolicy(cl))

	viper.Set("hydra.default_deny", true)
	assert.Equal(clientPolicy{Source: "default", All: false}, resolveClientPolicy(cl))
}

func TestUpdateRequiresAccess(t *testing.T) {
	r, hy := newClientsTestApp(t, nil)
	hy.seedClient(map[string]interface{}{"client_id": "wiki", "redirect_uris": []interface{}{"https://w.example.com/cb"}})
	in := webInput()
	in.Access = ""
	var verr clientInputError
	require.ErrorAs(t, r.updateOAuthClient("wiki", in, "admin"), &verr)
	assert.Contains(t, verr, "access")
}

func TestUpdateMachineReadOnly(t *testing.T) {
	r, hy := newClientsTestApp(t, nil)
	hy.seedClient(map[string]interface{}{"client_id": "batch", "grant_types": []interface{}{"client_credentials"}})
	assert.ErrorIs(t, r.updateOAuthClient("batch", webInput(), "admin"), errClientReadOnly)
	_, err := r.rotateOAuthClientSecret("batch", "admin")
	assert.ErrorIs(t, err, errClientReadOnly)
	assert.Zero(t, hy.clientWrites)
}

func TestRotateSecret(t *testing.T) {
	assert := assert.New(t)
	r, hy := newClientsTestApp(t, nil)
	id, first, err := r.createOAuthClient(webInput(), "admin")
	require.NoError(t, err)
	before := hy.storedClient(id)

	secret, err := r.rotateOAuthClientSecret(id, "admin")
	require.NoError(t, err)
	assert.NotEqual(first, secret)
	after := hy.storedClient(id)
	assert.Equal(secret, after["client_secret"])
	delete(before, "client_secret")
	delete(after, "client_secret")
	assert.Equal(before, after)

	in := webInput()
	in.Kind = kindPublic
	in.ID = "spa"
	_, _, err = r.createOAuthClient(in, "admin")
	require.NoError(t, err)
	_, err = r.rotateOAuthClientSecret("spa", "admin")
	assert.ErrorIs(err, errClientNoSecret)
}

func TestDeleteRevokesConsents(t *testing.T) {
	assert := assert.New(t)
	r, hy := newClientsTestApp(t, nil)
	hy.seedClient(map[string]interface{}{"client_id": "wiki", "client_name": "Wiki"})
	hy.seedConsentSession("walter", fakeConsentSession{ClientID: "wiki"})
	hy.seedConsentSession("walter", fakeConsentSession{ClientID: "other"})
	hy.seedConsentSession("skyler", fakeConsentSession{ClientID: "wiki"})

	require.NoError(t, r.deleteOAuthClient("wiki", "admin"))
	assert.Nil(hy.storedClient("wiki"))
	hy.mu.Lock()
	defer hy.mu.Unlock()
	assert.Empty(hy.consentSessions["skyler"])
	assert.Len(hy.consentSessions["walter"], 1)
	assert.Equal("other", hy.consentSessions["walter"][0].ClientID)
}

func TestHydraErrors(t *testing.T) {
	assert := assert.New(t)
	r, hy := newClientsTestApp(t, nil)
	hy.seedClient(map[string]interface{}{"client_id": "wiki"})

	in := webInput()
	in.ID = "wiki"
	_, _, err := r.createOAuthClient(in, "admin")
	assert.ErrorIs(err, errClientIDTaken)
	assert.Equal(map[string]interface{}{"client_id": "wiki"}, hy.storedClient("wiki"))

	assert.ErrorIs(r.updateOAuthClient("gone", webInput(), "admin"), errClientNotFound)
	_, err = r.rotateOAuthClientSecret("gone", "admin")
	assert.ErrorIs(err, errClientNotFound)
	assert.ErrorIs(r.deleteOAuthClient("gone", "admin"), errClientNotFound)
	hy.mu.Lock()
	assert.Equal(1, hy.clientWrites) // only the refused create
	hy.mu.Unlock()

	hy.Close()
	_, _, err = r.createOAuthClient(webInput(), "admin")
	assert.ErrorIs(err, errHydraUnavailable)
	assert.ErrorIs(r.updateOAuthClient("wiki", webInput(), "admin"), errHydraUnavailable)
	_, err = r.rotateOAuthClientSecret("wiki", "admin")
	assert.ErrorIs(err, errHydraUnavailable)
	assert.ErrorIs(r.deleteOAuthClient("wiki", "admin"), errHydraUnavailable)
}

func TestSecretNeverLogged(t *testing.T) {
	r, _ := newClientsTestApp(t, nil)
	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(saved) })

	id, first, err := r.createOAuthClient(webInput(), "admin")
	require.NoError(t, err)
	second, err := r.rotateOAuthClientSecret(id, "admin")
	require.NoError(t, err)
	require.NoError(t, r.deleteOAuthClient(id, "admin"))

	out := logs.String()
	assert.Contains(t, out, "AUDIT oauth client created")
	assert.Contains(t, out, "AUDIT oauth client secret rotated")
	assert.Contains(t, out, "AUDIT oauth client deleted")
	assert.Contains(t, out, "by=admin")
	assert.Contains(t, out, "client="+id)
	assert.NotContains(t, out, first)
	assert.NotContains(t, out, second)
}

func TestUnknownGroupRejected(t *testing.T) {
	r, hy := newClientsTestApp(t, nil)
	in := webInput()
	in.Groups = []string{"devs", "nosuchgroup"}
	_, _, err := r.createOAuthClient(in, "admin")
	var verr clientInputError
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr, "groups")
	assert.Zero(t, hy.clientWrites)

	hy.seedClient(map[string]interface{}{"client_id": "wiki", "redirect_uris": []interface{}{"https://w.example.com/cb"}})
	require.ErrorAs(t, r.updateOAuthClient("wiki", in, "admin"), &verr)
	assert.Zero(t, hy.clientWrites)
}

func TestCreateTrimsURIs(t *testing.T) {
	r, hy := newClientsTestApp(t, nil)
	in := webInput()
	in.RedirectURIs = []string{" https://wiki.example.com/cb ", "", "  "}
	in.PostLogoutURIs = []string{"", " https://wiki.example.com/bye"}
	id, _, err := r.createOAuthClient(in, "admin")
	require.NoError(t, err)
	cl := hy.storedClient(id)
	assert.Equal(t, []interface{}{"https://wiki.example.com/cb"}, cl["redirect_uris"])
	assert.Equal(t, []interface{}{"https://wiki.example.com/bye"}, cl["post_logout_redirect_uris"])

	in.RedirectURIs = []string{"", " "}
	var verr clientInputError
	_, _, err = r.createOAuthClient(in, "admin")
	require.ErrorAs(t, err, &verr)
	assert.Contains(t, verr, "redirect_uris")
}

func TestUpdateForeignClientIDs(t *testing.T) {
	r, hy := newClientsTestApp(t, nil)
	for _, id := range []string{"3f2504e0-4f89-11d3-9a0c-0305e82c3301", "Legacy-App"} {
		hy.seedClient(map[string]interface{}{"client_id": id, "redirect_uris": []interface{}{"https://w.example.com/cb"}})
		in := webInput()
		in.ID = id
		require.NoError(t, r.updateOAuthClient(id, in, "admin"), id)
		assert.Equal(t, "Wiki", hy.storedClient(id)["client_name"], id)
	}
}

func TestUnreadableClient(t *testing.T) {
	r, hy := newClientsTestApp(t, nil)
	hy.seedClient(map[string]interface{}{
		"client_id": "jwt", "redirect_uris": []interface{}{"https://w.example.com/cb"},
		"jwks": map[string]interface{}{"keys": []interface{}{map[string]interface{}{"kty": "RSA", "kid": "k1"}}},
	})
	err := r.updateOAuthClient("jwt", webInput(), "admin")
	assert.ErrorIs(t, err, errClientUnreadable)
	_, err = r.rotateOAuthClientSecret("jwt", "admin")
	assert.ErrorIs(t, err, errClientUnreadable)
	assert.ErrorIs(t, r.deleteOAuthClient("jwt", "admin"), errClientUnreadable)
	assert.Zero(t, hy.clientWrites)
}

func TestRotateOnlySecretMethods(t *testing.T) {
	r, hy := newClientsTestApp(t, nil)
	for method, ok := range map[string]bool{"client_secret_basic": true, "client_secret_post": true, "private_key_jwt": false, "none": false} {
		hy.seedClient(map[string]interface{}{"client_id": method, "token_endpoint_auth_method": method})
		_, err := r.rotateOAuthClientSecret(method, "admin")
		if ok {
			assert.NoError(t, err, method)
		} else {
			assert.ErrorIs(t, err, errClientNoSecret, method)
		}
	}
}

func TestUpdateKeepsMokeySubKeys(t *testing.T) {
	r, hy := newClientsTestApp(t, nil)
	hy.seedClient(map[string]interface{}{
		"client_id": "wiki", "redirect_uris": []interface{}{"https://w.example.com/cb"},
		"metadata": map[string]interface{}{"mokey": map[string]interface{}{"access": "groups", "groups": []interface{}{"ops"}, "future": "x"}},
	})
	in := webInput()
	in.Access, in.Groups = "all", nil
	require.NoError(t, r.updateOAuthClient("wiki", in, "admin"))
	assert.Equal(t, map[string]interface{}{"access": "all", "catalog": true, "future": "x"},
		hy.storedClient("wiki")["metadata"].(map[string]interface{})["mokey"])
}
