package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	hydra "github.com/ory/hydra-client-go/v26"
)

type clientKind string

const (
	kindWeb     clientKind = "web"
	kindPublic  clientKind = "public"
	kindMachine clientKind = "machine"
	kindOther   clientKind = "other"
)

var (
	errHydraUnavailable     = errors.New("hydra admin API unavailable")
	errClientNotFound       = errors.New("oauth client not found")
	errClientIDTaken        = errors.New("oauth client ID already taken")
	errClientReadOnly       = errors.New("machine clients are read-only")
	errClientNoSecret       = errors.New("public clients have no secret")
	errClientAccessInConfig = errors.New("access of this client is set in mokey.toml")
	errClientUnreadable     = errors.New("Hydra returned a client mokey can't read; manage it with the Hydra CLI")
)

// clientInputError maps form fields to translation keys.
type clientInputError map[string]string

func (e clientInputError) Error() string {
	fields := make([]string, 0, len(e))
	for f := range e {
		fields = append(fields, f)
	}
	slices.Sort(fields)
	return "invalid oauth client input: " + strings.Join(fields, ", ")
}

// clientInput is what the admin form manages. Kind is only used on create;
// Access "" on update leaves metadata.mokey as it is.
type clientInput struct {
	ID, Name, URI                string
	Kind                         clientKind
	RedirectURIs, PostLogoutURIs []string
	Scopes                       []string
	Access                       string
	Groups                       []string
	Catalog                      bool
	authNone                     bool // update of a client with no secret: custom-scheme redirects allowed
}

var (
	clientIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	scopeTokenPattern = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]+$`)
)

// clientKindOf: Hydra defaults empty grant and response types to
// authorization_code and code.
func clientKindOf(cl *hydra.OAuth2Client) clientKind {
	grants := cl.GetGrantTypes()
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	if !slices.ContainsFunc(grants, func(g string) bool { return g != "client_credentials" }) {
		return kindMachine
	}
	responses := cl.GetResponseTypes()
	userFlow := slices.Contains(grants, "authorization_code") &&
		!slices.ContainsFunc(grants, func(g string) bool { return g != "authorization_code" && g != "refresh_token" }) &&
		(len(responses) == 0 || slices.Equal(responses, []string{"code"}))
	if !userFlow {
		return kindOther
	}
	switch cl.GetTokenEndpointAuthMethod() {
	case "", "client_secret_basic":
		return kindWeb
	case "none":
		return kindPublic
	}
	return kindOther
}

func validRedirectURI(s string, public bool) bool {
	u, err := url.Parse(s)
	if err != nil || strings.Contains(s, "#") || u.Scheme == "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Hostname() != ""
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	// RFC 8252 7.1: private-use schemes are reverse domain names, which
	// also keeps javascript: and data: out
	return public && strings.Contains(u.Scheme, ".")
}

func (in *clientInput) validate() map[string]string {
	errs := map[string]string{}
	if in.ID != "" && !clientIDPattern.MatchString(in.ID) {
		errs["id"] = "admin_apps.err_id"
	}
	if in.Kind != kindWeb && in.Kind != kindPublic && in.Kind != kindOther {
		errs["kind"] = "admin_apps.err_kind"
	}
	if in.URI != "" {
		if u, err := url.Parse(in.URI); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
			errs["uri"] = "admin_apps.err_uri"
		}
	}
	public := in.Kind == kindPublic || in.authNone
	if len(in.RedirectURIs) == 0 {
		errs["redirect_uris"] = "admin_apps.err_redirect_required"
	}
	for _, s := range in.RedirectURIs {
		if !validRedirectURI(s, public) {
			errs["redirect_uris"] = "admin_apps.err_redirect_uri"
		}
	}
	for _, s := range in.PostLogoutURIs {
		if !validRedirectURI(s, public) {
			errs["post_logout_redirect_uris"] = "admin_apps.err_redirect_uri"
		}
	}
	for _, s := range in.Scopes {
		if !scopeTokenPattern.MatchString(s) {
			errs["scopes"] = "admin_apps.err_scope"
		}
	}
	switch in.Access {
	case "", "all":
	case "groups":
		if len(in.Groups) == 0 {
			errs["groups"] = "admin_apps.err_groups_required"
		}
	default:
		errs["access"] = "admin_apps.err_access"
	}
	return errs
}

func newClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hydraError maps a Hydra admin call failure to the typed errors. Response
// bodies are left out: on create and set they echo the secret.
func hydraError(resp *http.Response, err error) error {
	if err == nil {
		return nil
	}
	if resp == nil {
		return fmt.Errorf("%w: %v", errHydraUnavailable, err)
	}
	switch {
	case resp.StatusCode < 300:
		return errClientUnreadable
	case resp.StatusCode == http.StatusNotFound:
		return errClientNotFound
	case resp.StatusCode == http.StatusConflict:
		return errClientIDTaken
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: %s", errHydraUnavailable, resp.Status)
	}
	return fmt.Errorf("hydra admin API: %s", resp.Status)
}

// checkClientGroups adds a field error when a group isn't in FreeIPA.
func (r *Router) checkClientGroups(in *clientInput, errs map[string]string) error {
	if in.Access != "groups" {
		return nil
	}
	for _, g := range in.Groups {
		if _, err := r.adminClient.GroupShow(g); err != nil {
			if entryGone(err) {
				errs["groups"] = "admin_apps.err_group_unknown"
				return nil
			}
			return err
		}
	}
	return nil
}

func trimLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func normalizeClientInput(in *clientInput) {
	in.RedirectURIs = trimLines(in.RedirectURIs)
	in.PostLogoutURIs = trimLines(in.PostLogoutURIs)
	scopes := []string{"openid"}
	for _, s := range in.Scopes {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	in.Scopes = scopes
	var groups []string
	for _, g := range in.Groups {
		if g = strings.TrimSpace(g); g != "" && !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	in.Groups = groups
}

// applyClientInput sets the fields mokey manages and nothing else.
func applyClientInput(cl *hydra.OAuth2Client, in clientInput) {
	cl.ClientName = &in.Name
	cl.ClientUri = &in.URI
	cl.RedirectUris = in.RedirectURIs
	cl.PostLogoutRedirectUris = in.PostLogoutURIs
	scope := strings.Join(in.Scopes, " ")
	cl.Scope = &scope
	if in.Access != "" {
		catalog := in.Catalog
		m := clientMeta{Access: in.Access, Catalog: &catalog}
		if in.Access == "groups" {
			m.Groups = in.Groups
		}
		writeClientMeta(cl, m)
	}
}

// setConfigClientMeta, for clients whose access is set in mokey.toml, sets
// catalog and mirrors the entry's groups so access stays the same once the
// entry is removed.
func setConfigClientMeta(cl *hydra.OAuth2Client, mirror bool, groups []string, catalog bool) {
	mergeClientMeta(cl, func(m map[string]interface{}) {
		m["catalog"] = catalog
		if mirror {
			m["access"] = "groups"
			m["groups"] = groups
		}
	})
}

func accessSummary(cl *hydra.OAuth2Client) string {
	p := resolveClientPolicy(cl)
	switch {
	case p.Source == "config":
		return "mokey.toml: " + strings.Join(p.Groups, ",")
	case p.All:
		return "all"
	}
	return "groups: " + strings.Join(p.Groups, ",")
}

func auditClient(msg, by string, cl *hydra.OAuth2Client) {
	slog.Info("AUDIT oauth client "+msg,
		"by", by,
		"client", cl.GetClientId(),
		"name", cl.GetClientName(),
		"type", string(clientKindOf(cl)),
		"access", accessSummary(cl),
	)
}

// prepareClientInput validates, normalizes and checks groups in FreeIPA.
func (r *Router) prepareClientInput(in *clientInput) error {
	normalizeClientInput(in)
	errs := in.validate()
	if len(errs) == 0 {
		if err := r.checkClientGroups(in, errs); err != nil {
			return err
		}
	}
	if len(errs) > 0 {
		return clientInputError(errs)
	}
	return nil
}

func (r *Router) createOAuthClient(in clientInput, by string) (id, secret string, err error) {
	if err := r.prepareClientInput(&in); err != nil {
		return "", "", err
	}
	errs := clientInputError{}
	if in.Kind != kindWeb && in.Kind != kindPublic {
		errs["kind"] = "admin_apps.err_kind"
	}
	if in.Access == "" {
		errs["access"] = "admin_apps.err_access"
	}
	if len(errs) > 0 {
		return "", "", errs
	}

	cl := hydra.OAuth2Client{
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
	}
	if in.ID != "" {
		cl.ClientId = &in.ID
	}
	method := "none"
	if in.Kind == kindWeb {
		method = "client_secret_basic"
		if secret, err = newClientSecret(); err != nil {
			return "", "", err
		}
		cl.ClientSecret = &secret
	}
	cl.TokenEndpointAuthMethod = &method
	applyClientInput(&cl, in)

	created, resp, err := r.hydraClient.OAuth2API.CreateOAuth2Client(context.Background()).OAuth2Client(cl).Execute()
	if err := hydraError(resp, err); err != nil {
		return "", "", err
	}
	created.ClientSecret = nil
	auditClient("created", by, created)
	return created.GetClientId(), secret, nil
}

// getManagedClient fetches a client mokey may change.
func (r *Router) getManagedClient(id string) (*hydra.OAuth2Client, error) {
	cl, resp, err := r.hydraClient.OAuth2API.GetOAuth2Client(context.Background(), id).Execute()
	if err := hydraError(resp, err); err != nil {
		return nil, err
	}
	if clientKindOf(cl) == kindMachine {
		return nil, errClientReadOnly
	}
	return cl, nil
}

// putClient replaces the whole client. Without client_secret in the body
// Hydra v2 keeps the stored secret.
func (r *Router) putClient(cl *hydra.OAuth2Client) error {
	_, resp, err := r.hydraClient.OAuth2API.SetOAuth2Client(context.Background(), cl.GetClientId()).OAuth2Client(*cl).Execute()
	return hydraError(resp, err)
}

func (r *Router) updateOAuthClient(id string, in clientInput, by string) error {
	cl, err := r.getManagedClient(id)
	if err != nil {
		return err
	}
	in.Kind = clientKindOf(cl)
	in.authNone = cl.GetTokenEndpointAuthMethod() == "none"
	in.ID = "" // only checked on create: clients made elsewhere use other IDs
	cfg, inConfig := configClientPolicy(id)
	if inConfig && (in.Access != "" || len(in.Groups) > 0) {
		return errClientAccessInConfig
	} else if !inConfig && in.Access == "" {
		return clientInputError{"access": "admin_apps.err_access"}
	}
	if err := r.prepareClientInput(&in); err != nil {
		return err
	}

	applyClientInput(cl, in)
	if inConfig {
		// an invalid config denies every client; that's not worth keeping
		_, cfgErr := configPolicies()
		setConfigClientMeta(cl, cfgErr == nil, cfg.Groups, in.Catalog)
	}
	cl.ClientSecret = nil
	if err := r.putClient(cl); err != nil {
		return err
	}
	auditClient("updated", by, cl)
	return nil
}

func (r *Router) rotateOAuthClientSecret(id, by string) (string, error) {
	cl, err := r.getManagedClient(id)
	if err != nil {
		return "", err
	}
	if m := cl.GetTokenEndpointAuthMethod(); m != "" && m != "client_secret_basic" && m != "client_secret_post" {
		return "", errClientNoSecret
	}
	secret, err := newClientSecret()
	if err != nil {
		return "", err
	}
	cl.ClientSecret = &secret
	if err := r.putClient(cl); err != nil {
		return "", err
	}
	cl.ClientSecret = nil
	auditClient("secret rotated", by, cl)
	return secret, nil
}

// deleteOAuthClient relies on Hydra: deleting a client cascades to its
// consent sessions and tokens (foreign keys on hydra_client), and Hydra's
// consent revocation API needs a subject.
func (r *Router) deleteOAuthClient(id, by string) error {
	cl, err := r.getManagedClient(id)
	if err != nil {
		return err
	}
	resp, err := r.hydraClient.OAuth2API.DeleteOAuth2Client(context.Background(), id).Execute()
	if err := hydraError(resp, err); err != nil {
		return err
	}
	auditClient("deleted", by, cl)
	return nil
}
