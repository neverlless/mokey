//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// OAuth client admin against the real Ory Hydra of test/hydra.compose.yml:
// clients created, edited, rotated and deleted on mokey's Apps page, checked
// in Hydra's admin API and at its token endpoint, and authorization code
// flows through mokey's login and consent.

var (
	hydraAdmin  = envOr("MOKEY_IT_HYDRA_ADMIN", "http://localhost:4445")
	hydraPublic = envOr("MOKEY_IT_HYDRA_PUBLIC", "http://localhost:4444")
)

const hydraRedirect = "http://localhost:9999/cb"

func hydraStand(t *testing.T) {
	t.Helper()
	stand(t)
	if os.Getenv("MOKEY_IT_HYDRA") == "" {
		t.Skip("MOKEY_IT_HYDRA is not set")
	}
}

// hydraDo calls Hydra without following redirects and decodes a JSON body
// into v when v is not nil.
func hydraDo(t *testing.T, req *http.Request, v any) (int, string) {
	t.Helper()
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %s", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if v != nil && len(b) > 0 {
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatalf("%s %s: %s: %s", req.Method, req.URL, err, b)
		}
	}
	return resp.StatusCode, string(b)
}

func hydraJSON(t *testing.T, method, path, body string, v any) int {
	t.Helper()
	req, _ := http.NewRequest(method, hydraAdmin+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	code, _ := hydraDo(t, req, v)
	return code
}

func hydraForm(t *testing.T, u string, form url.Values, id, secret string, v any) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	}
	return hydraDo(t, req, v)
}

type hydraClient struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	RedirectURIs            []string `json:"redirect_uris"`
	AllowedCORSOrigins      []string `json:"allowed_cors_origins"`
	Scope                   string   `json:"scope"`
	Metadata                struct {
		Mokey struct {
			Access string   `json:"access"`
			Groups []string `json:"groups"`
		} `json:"mokey"`
	} `json:"metadata"`
}

func getHydraClient(t *testing.T, id string) (int, hydraClient) {
	t.Helper()
	var cl hydraClient
	code := hydraJSON(t, "GET", "/admin/clients/"+url.PathEscape(id), "", &cl)
	return code, cl
}

// secretError is the OAuth error for a token request with a bogus code:
// invalid_grant when Hydra accepted the client secret, invalid_client when not.
func secretError(t *testing.T, id, secret string) string {
	t.Helper()
	var e struct{ Error string }
	hydraForm(t, hydraPublic+"/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {"bogus"}, "redirect_uri": {hydraRedirect},
	}, id, secret, &e)
	return e.Error
}

var monoRe = regexp.MustCompile(`<span class="mokey-mono">([^<]+)</span>`)

// appSecret reads the client secret from mokey's secret page: the second
// copy row, after the client ID.
func appSecret(t *testing.T, body string) string {
	t.Helper()
	m := monoRe.FindAllStringSubmatch(body, -1)
	if len(m) < 2 {
		t.Fatalf("no secret on the page: %s", body)
	}
	return html.UnescapeString(m[1][1])
}

func appForm(id, kind, name, group, scopes string) url.Values {
	return url.Values{
		"id": {id}, "name": {name}, "kind": {kind},
		"redirect_uris": {hydraRedirect}, "scopes": strings.Fields(scopes),
		"access": {"groups"}, "groups": {group}, "catalog": {"1"},
	}
}

// authorize runs an authorization code flow from Hydra through mokey with
// the cookies of c. It stops at the client's redirect URI (returning its
// query), at a consent challenge when stopAtConsent, or at the first page
// that is not a redirect (returning its status and body).
func authorize(t *testing.T, c *client, q url.Values, stopAtConsent bool) (url.Values, int, string) {
	t.Helper()
	q.Set("response_type", "code")
	q.Set("redirect_uri", hydraRedirect)
	q.Set("state", "it-state-"+randHex(4))
	next := hydraPublic + "/oauth2/auth?" + q.Encode()
	for range 20 {
		if strings.HasPrefix(next, hydraRedirect) {
			u, _ := url.Parse(next)
			return u.Query(), 0, ""
		}
		u, _ := url.Parse(next)
		if stopAtConsent && u.Query().Get("consent_challenge") != "" {
			return u.Query(), 0, ""
		}
		req, _ := http.NewRequest("GET", next, nil)
		resp, err := c.http.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %s", next, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || loc == "" {
			return nil, resp.StatusCode, string(b)
		}
		l, _ := u.Parse(loc)
		next = l.String()
	}
	t.Fatal("authorization flow: too many redirects")
	return nil, 0, ""
}

type tokens struct {
	AccessToken, RefreshToken, Error string
}

func exchange(t *testing.T, id, secret string, form url.Values) tokens {
	t.Helper()
	var tk struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	hydraForm(t, hydraPublic+"/oauth2/token", form, id, secret, &tk)
	return tokens{tk.AccessToken, tk.RefreshToken, tk.Error}
}

func introspectActive(t *testing.T, token string) bool {
	t.Helper()
	var r struct{ Active bool }
	hydraForm(t, hydraAdmin+"/admin/oauth2/introspect", url.Values{"token": {token}}, "", "", &r)
	return r.Active
}

func consentClients(t *testing.T, subject string) []string {
	t.Helper()
	var sessions []struct {
		ConsentRequest struct {
			Client struct {
				ClientID string `json:"client_id"`
			} `json:"client"`
		} `json:"consent_request"`
	}
	if code := hydraJSON(t, "GET", "/admin/oauth2/auth/sessions/consent?subject="+url.QueryEscape(subject), "", &sessions); code != http.StatusOK {
		t.Fatalf("list consent sessions: %d", code)
	}
	var ids []string
	for _, s := range sessions {
		ids = append(ids, s.ConsentRequest.Client.ClientID)
	}
	return ids
}

func TestHydraWebClientLifecycle(t *testing.T) {
	hydraStand(t)
	admin := newUser(t)
	mustIPA(t, "group-add-member", "admins", "--users="+admin.uid)
	member, outsider := newUser(t), newUser(t)
	group := "ithy" + randHex(3)
	mustIPA(t, "group-add", group, "--desc=mokey hydra test")
	t.Cleanup(func() { _, _ = ipaCmd("", "group-del", group) })
	mustIPA(t, "group-add-member", group, "--users="+member.uid)

	ac := login(t, admin.uid, admin.password)
	id := "it-web-" + randHex(3)
	t.Cleanup(func() { hydraJSON(t, "DELETE", "/admin/clients/"+id, "", nil) })

	// a. create
	code, body := ac.hx("/admin/apps", appForm(id, "web", "IT web", group, "openid profile offline_access"))
	if code != http.StatusOK {
		t.Fatalf("create: %d: %s", code, body)
	}
	secret := appSecret(t, body)
	code, cl := getHydraClient(t, id)
	if code != http.StatusOK {
		t.Fatalf("client not in Hydra: %d", code)
	}
	if cl.TokenEndpointAuthMethod != "client_secret_basic" ||
		strings.Join(cl.GrantTypes, " ") != "authorization_code refresh_token" ||
		strings.Join(cl.ResponseTypes, " ") != "code" ||
		strings.Join(cl.RedirectURIs, " ") != hydraRedirect ||
		cl.Metadata.Mokey.Access != "groups" || strings.Join(cl.Metadata.Mokey.Groups, " ") != group {
		t.Fatalf("client in Hydra: %+v", cl)
	}
	if e := secretError(t, id, secret); e != "invalid_grant" {
		t.Fatalf("new secret: want invalid_grant, got %q", e)
	}
	if e := secretError(t, id, "wrong"); e != "invalid_client" {
		t.Fatalf("wrong secret: want invalid_client, got %q", e)
	}

	// b. update keeps fields mokey doesn't manage, and the secret
	patch := `[{"op":"replace","path":"/allowed_cors_origins","value":["https://cors.example.test"]}]`
	if code := hydraJSON(t, "PATCH", "/admin/clients/"+id, patch, nil); code != http.StatusOK {
		t.Fatalf("patch in Hydra: %d", code)
	}
	f := appForm(id, "", "IT web renamed", group, "openid profile offline_access")
	f.Del("id")
	f.Del("kind")
	if code, body := ac.hx("/admin/apps/"+id, f); code != http.StatusOK {
		t.Fatalf("update: %d: %s", code, body)
	}
	_, cl = getHydraClient(t, id)
	if cl.ClientName != "IT web renamed" || strings.Join(cl.AllowedCORSOrigins, " ") != "https://cors.example.test" {
		t.Fatalf("after update: %+v", cl)
	}
	if e := secretError(t, id, secret); e != "invalid_grant" {
		t.Fatalf("secret after update: want invalid_grant, got %q", e)
	}

	// c. rotate: the new secret works at once, the old one stops
	code, body = ac.hx("/admin/apps/"+id+"/rotate", nil)
	if code != http.StatusOK {
		t.Fatalf("rotate: %d: %s", code, body)
	}
	old := secret
	secret = appSecret(t, body)
	if secret == old {
		t.Fatal("rotate returned the old secret")
	}
	if e := secretError(t, id, secret); e != "invalid_grant" {
		t.Fatalf("rotated secret: want invalid_grant, got %q", e)
	}
	if e := secretError(t, id, old); e != "invalid_client" {
		t.Fatalf("old secret after rotate: want invalid_client, got %q", e)
	}

	// d. the consent request carries metadata.mokey; member in, outsider out
	q := url.Values{"client_id": {id}, "scope": {"openid offline_access"}}
	oc := login(t, outsider.uid, outsider.password)
	cq, _, body := authorize(t, oc, q, true)
	if cq == nil {
		t.Fatalf("outsider flow stopped before consent: %s", body)
	}
	var consent struct {
		Client struct {
			Metadata map[string]any `json:"metadata"`
		} `json:"client"`
	}
	if code := hydraJSON(t, "GET", "/admin/oauth2/auth/requests/consent?consent_challenge="+url.QueryEscape(cq.Get("consent_challenge")), "", &consent); code != http.StatusOK {
		t.Fatalf("consent request: %d", code)
	}
	if m, _ := consent.Client.Metadata["mokey"].(map[string]any); m["access"] != "groups" {
		t.Fatalf("consent request client metadata: %v", consent.Client.Metadata)
	}
	if code, _ := oc.get("/oauth/consent?consent_challenge=" + url.QueryEscape(cq.Get("consent_challenge"))); code != http.StatusForbidden {
		t.Fatalf("outsider consent: want 403, got %d", code)
	}

	mc := login(t, member.uid, member.password)
	cb, code, body := authorize(t, mc, q, false)
	if cb.Get("code") == "" {
		t.Fatalf("member flow: %v %d %s", cb, code, body)
	}
	tk := exchange(t, id, secret, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Get("code")}, "redirect_uri": {hydraRedirect}})
	if tk.AccessToken == "" || tk.RefreshToken == "" {
		t.Fatalf("token exchange: %+v", tk)
	}
	if !introspectActive(t, tk.AccessToken) {
		t.Fatal("access token inactive before delete")
	}
	t.Logf("consent sessions of the member before delete: %v", consentClients(t, member.uid))

	// e. delete removes the client's consent sessions and tokens
	if code, body := ac.hx("/admin/apps/"+id+"/delete", nil); code != http.StatusOK {
		t.Fatalf("delete: %d: %s", code, body)
	}
	if code, _ := getHydraClient(t, id); code != http.StatusNotFound {
		t.Fatalf("client after delete: %d", code)
	}
	for _, c := range consentClients(t, member.uid) {
		if c == id {
			t.Fatal("consent session left after delete")
		}
	}
	if introspectActive(t, tk.AccessToken) {
		t.Fatal("access token active after delete")
	}
	if r := exchange(t, id, secret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken}}); r.AccessToken != "" {
		t.Fatal("refresh token works after delete")
	}
}

// f. oauth2.pkce.enforced_for_public_clients in test/hydra/hydra.yml
func TestHydraPublicClientNeedsPKCE(t *testing.T) {
	hydraStand(t)
	admin := newUser(t)
	mustIPA(t, "group-add-member", "admins", "--users="+admin.uid)
	ac := login(t, admin.uid, admin.password)
	id := "it-pub-" + randHex(3)
	t.Cleanup(func() { hydraJSON(t, "DELETE", "/admin/clients/"+id, "", nil) })
	if code, body := ac.hx("/admin/apps", appForm(id, "public", "IT public", policyGroup, "openid")); code != http.StatusOK {
		t.Fatalf("create: %d: %s", code, body)
	}
	if _, cl := getHydraClient(t, id); cl.TokenEndpointAuthMethod != "none" {
		t.Fatalf("public client in Hydra: %+v", cl)
	}

	// Hydra checks PKCE only after login and consent, when it issues the code
	q := url.Values{"client_id": {id}, "scope": {"openid"}}
	cb, code, body := authorize(t, ac, q, false)
	if cb.Get("error") != "invalid_request" {
		t.Fatalf("flow without PKCE: want invalid_request at the redirect URI, got %v %d %s", cb, code, body)
	}
	t.Logf("without PKCE: %s: %s", cb.Get("error"), cb.Get("error_description"))

	verifier := randHex(32)
	sum := sha256.Sum256([]byte(verifier))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	cb, code, body = authorize(t, ac, q, false)
	if cb.Get("code") == "" {
		t.Fatalf("flow with PKCE: %v %d %s", cb, code, body)
	}
	tk := exchange(t, "", "", url.Values{"grant_type": {"authorization_code"}, "code": {cb.Get("code")},
		"redirect_uri": {hydraRedirect}, "client_id": {id}, "code_verifier": {verifier}})
	if tk.AccessToken == "" {
		t.Fatalf("token exchange with PKCE: %+v", tk)
	}
}
