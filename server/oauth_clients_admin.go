package server

import (
	"encoding/json"
	"errors"
	"html"
	"log/slog"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
	hydra "github.com/ory/hydra-client-go/v26"
	"github.com/spf13/viper"
)

var appScopes = []string{"openid", "profile", "email", "offline_access", "ssh"}

// appNarrowSweepKey keeps narrowing saves from running sweeps side by side.
const appNarrowSweepKey = "consent-sweep-narrow"

// appsAdminOn gates the /admin/apps pages, routes and nav item.
func (r *Router) appsAdminOn() bool {
	return viper.GetBool("hydra.manage_clients") && r.hydraClient != nil && viper.GetBool("admin.enabled")
}

type appRow struct {
	ID, Name string
	Kind     clientKind
	Groups   []string
	Everyone bool
	Config   bool // access set in mokey.toml
	Missing  bool // config entry without a Hydra client
}

// appForm is the admin form for one client; Errors maps fields to
// translation keys.
type appForm struct {
	New                          bool
	ID, Name, URI, Title         string
	Kind                         clientKind
	RedirectURIs, PostLogoutURIs string
	Scopes                       map[string]bool
	OtherScopes                  string
	Access                       string
	Groups                       []string
	Catalog                      bool
	Config                       bool
	ConfigGroups                 []string
	Errors                       map[string]string
	Narrow                       bool
}

func (a appRow) Path() string     { return url.PathEscape(a.ID) }
func (f *appForm) Path() string   { return url.PathEscape(f.ID) }
func (s *appSecret) Path() string { return url.PathEscape(s.ID) }

func (f *appForm) CanRotate() bool { return !f.New && f.Kind == kindWeb }

func (f *appForm) input() clientInput {
	in := clientInput{
		ID: f.ID, Name: f.Name, URI: f.URI, Kind: f.Kind,
		RedirectURIs:   strings.Split(f.RedirectURIs, "\n"),
		PostLogoutURIs: strings.Split(f.PostLogoutURIs, "\n"),
		Access:         f.Access, Groups: f.Groups, Catalog: f.Catalog,
	}
	for _, s := range appScopes {
		if f.Scopes[s] {
			in.Scopes = append(in.Scopes, s)
		}
	}
	in.Scopes = append(in.Scopes, strings.Fields(f.OtherScopes)...)
	if f.Config {
		in.Access, in.Groups = "", nil
	}
	return in
}

type appCopyRow struct {
	Label, Value string
	Secret       bool
}

// appSecret is the secret page, rendered once in the POST response and
// never stored.
type appSecret struct {
	ID, Name, Secret string
	Kind             string // "create" | "rotate"
}

func appRows(clients []hydra.OAuth2Client) []appRow {
	rows := make([]appRow, 0, len(clients))
	seen := map[string]bool{}
	for i := range clients {
		cl := &clients[i]
		p := resolveClientPolicy(cl)
		row := appRow{ID: cl.GetClientId(), Name: cl.GetClientName(), Kind: clientKindOf(cl), Everyone: p.All, Config: p.Source == "config"}
		if !p.All {
			row.Groups = p.Groups
		}
		if row.Name == "" {
			row.Name = row.ID
		}
		seen[row.ID] = true
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(a, b int) bool { return strings.ToLower(rows[a].Name) < strings.ToLower(rows[b].Name) })
	// an invalid config already shows as deny on every client
	config, _ := configPolicies()
	for _, p := range config {
		if !seen[p.ClientID] {
			seen[p.ClientID] = true
			rows = append(rows, appRow{ID: p.ClientID, Name: p.ClientID, Groups: p.Groups, Config: true, Missing: true})
		}
	}
	return rows
}

func formFromClient(cl *hydra.OAuth2Client) *appForm {
	f := &appForm{
		ID: cl.GetClientId(), Name: cl.GetClientName(), URI: cl.GetClientUri(), Kind: clientKindOf(cl),
		RedirectURIs:   strings.Join(cl.RedirectUris, "\n"),
		PostLogoutURIs: strings.Join(cl.PostLogoutRedirectUris, "\n"),
		Scopes:         map[string]bool{"openid": true},
		Catalog:        true,
	}
	f.Title = f.Name
	if f.Title == "" {
		f.Title = f.ID
	}
	var other []string
	for _, s := range strings.Fields(cl.GetScope()) {
		if slices.Contains(appScopes, s) {
			f.Scopes[s] = true
		} else {
			other = append(other, s)
		}
	}
	f.OtherScopes = strings.Join(other, " ")
	if m, err := readClientMeta(cl); err == nil && m != nil && m.Catalog != nil {
		f.Catalog = *m.Catalog
	}
	p := resolveClientPolicy(cl)
	f.Config = p.Source == "config"
	if f.Config {
		f.ConfigGroups = p.Groups
	} else if p.All {
		f.Access = "all"
	} else {
		f.Access, f.Groups = "groups", p.Groups
	}
	return f
}

func formFromRequest(c fiber.Ctx) *appForm {
	multi := func(key string) []string {
		var out []string
		for _, v := range c.Request().PostArgs().PeekMulti(key) {
			out = append(out, string(v))
		}
		return out
	}
	f := &appForm{
		ID:             strings.TrimSpace(c.FormValue("id")),
		Name:           strings.TrimSpace(c.FormValue("name")),
		URI:            strings.TrimSpace(c.FormValue("uri")),
		Kind:           clientKind(c.FormValue("kind")),
		RedirectURIs:   c.FormValue("redirect_uris"),
		PostLogoutURIs: c.FormValue("post_logout_redirect_uris"),
		Scopes:         map[string]bool{"openid": true},
		OtherScopes:    c.FormValue("other_scopes"),
		Access:         c.FormValue("access"),
		Catalog:        c.FormValue("catalog") == "1",
	}
	for _, s := range multi("scopes") {
		f.Scopes[s] = true
	}
	f.Groups = multi("groups")
	f.Groups = append(f.Groups, strings.FieldsFunc(c.FormValue("groups_add"), func(r rune) bool { return r == ',' || r == ' ' })...)
	return f
}

// narrows is true when someone the old policy admits may lose access.
func narrows(old clientPolicy, in clientInput) bool {
	if in.Access == "all" {
		return false
	}
	if old.All {
		return true
	}
	for _, g := range old.Groups {
		if !slices.ContainsFunc(in.Groups, func(h string) bool { return strings.EqualFold(g, h) }) {
			return true
		}
	}
	return false
}

func appErrorKey(err error) string {
	switch {
	case errors.Is(err, errHydraUnavailable):
		return "admin_apps.err_hydra"
	case errors.Is(err, errClientNotFound):
		return "admin_apps.err_not_found"
	case errors.Is(err, errClientReadOnly):
		return "admin_apps.err_read_only"
	case errors.Is(err, errClientUnreadable):
		return "admin_apps.err_unreadable"
	case errors.Is(err, errClientNoSecret):
		return "admin_apps.err_no_secret"
	case errors.Is(err, errClientAccessInConfig):
		return "admin_apps.err_access_in_config"
	}
	return "admin_apps.err_failed"
}

func (r *Router) appsPageVars(c fiber.Ctx, page string) fiber.Map {
	vars := r.shellVars(c, "admin/apps")
	vars["ap_page"] = page
	return vars
}

func (r *Router) AdminApps(c fiber.Ctx) error {
	vars := r.appsPageVars(c, "list")
	clients, err := r.listOAuthClients()
	if err != nil {
		slog.Error("Failed to list OAuth clients", "err", err)
		vars["ap_error"] = TC(c, "admin_apps.err_hydra")
	} else {
		vars["ap_rows"] = appRows(clients)
	}
	return c.Render("index.html", vars)
}

// renderAppForm renders the whole page, or only the form for an htmx POST.
func (r *Router) renderAppForm(c fiber.Ctx, f *appForm, alert string) error {
	vars := r.appsPageVars(c, "form")
	vars["ap_form"] = f
	vars["ap_scopes"] = appScopes
	vars["ap_error"] = alert
	if f != nil && !f.Config {
		names, err := r.groupNames()
		if err != nil {
			slog.Error("Failed to list FreeIPA groups for the app form", "err", err)
		}
		vars["ap_groups"] = names
	}
	if c.Method() == fiber.MethodPost {
		return c.Render("admin-app-form.html", vars)
	}
	return c.Render("index.html", vars)
}

// groupNames lists every FreeIPA group name.
// shortcut: raw group_find because goipa's GroupFind forces all=true and
// members; switch back once goipa honours no_members/pkey_only.
func (r *Router) groupNames() ([]string, error) {
	res, err := r.adminClient.RPC("group_find", []string{""}, ipa.Options{"pkey_only": true, "sizelimit": 0})
	if err != nil || res.Result == nil {
		return nil, err
	}
	var entries []struct {
		CN []string `json:"cn"`
	}
	if err := json.Unmarshal(res.Result.Data, &entries); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if len(e.CN) > 0 {
			names = append(names, e.CN[0])
		}
	}
	return names, nil
}

// appID is the client ID from the path; templates PathEscape it.
func appID(c fiber.Ctx) string {
	id, err := url.PathUnescape(c.Params("id"))
	if err != nil {
		return c.Params("id")
	}
	return id
}

// renderAppSecret answers create and rotate with the secret page itself,
// so the secret is never stored and no URL can show it again.
func (r *Router) renderAppSecret(c fiber.Ctx, s appSecret) error {
	c.Set("Cache-Control", "no-store")
	vars := r.appsPageVars(c, "secret")
	vars["ap_secret"] = &s
	rows := []appCopyRow{{Label: TC(c, "admin_apps.client_id"), Value: s.ID}}
	if s.Secret != "" {
		rows = append(rows, appCopyRow{Label: TC(c, "admin_apps.client_secret"), Value: s.Secret, Secret: true})
	}
	if u := r.hydraPublicURL; u != "" {
		vars["ap_public_url"] = true
		rows = append(rows,
			appCopyRow{Label: TC(c, "admin_apps.issuer"), Value: u + "/"},
			appCopyRow{Label: TC(c, "admin_apps.discovery"), Value: u + "/.well-known/openid-configuration"},
			appCopyRow{Label: TC(c, "admin_apps.authorize"), Value: u + "/oauth2/auth"},
			appCopyRow{Label: TC(c, "admin_apps.token"), Value: u + "/oauth2/token"},
		)
	}
	vars["ap_copy"] = rows
	return c.Render("admin-app-secret.html", vars)
}

// appFormError shows err as field errors or as an alert above the form.
func (r *Router) appFormError(c fiber.Ctx, f *appForm, err error) error {
	var fields clientInputError
	switch {
	case errors.As(err, &fields):
		f.Errors = fields
		return r.renderAppForm(c, f, "")
	case errors.Is(err, errClientIDTaken):
		f.Errors = map[string]string{"id": "admin_apps.err_id_taken"}
		return r.renderAppForm(c, f, "")
	}
	slog.Error("OAuth client change failed", "client", f.ID, "by", r.username(c), "err", err)
	return r.renderAppForm(c, f, TC(c, appErrorKey(err)))
}

func (r *Router) AdminAppNew(c fiber.Ctx) error {
	return r.renderAppForm(c, &appForm{New: true, Kind: kindWeb, Access: "groups", Catalog: true,
		Scopes: map[string]bool{"openid": true, "profile": true, "email": true}}, "")
}

func (r *Router) AdminAppEdit(c fiber.Ctx) error {
	cl, err := r.getManagedClient(appID(c))
	if errors.Is(err, errClientNotFound) || errors.Is(err, errClientReadOnly) {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	if err != nil {
		slog.Error("Failed to read OAuth client", "client", appID(c), "err", err)
		return r.renderAppForm(c, nil, TC(c, appErrorKey(err)))
	}
	return r.renderAppForm(c, formFromClient(cl), "")
}

func hxRedirect(c fiber.Ctx, to string) error {
	c.Set("HX-Redirect", to)
	return c.SendString("")
}

func (r *Router) AdminAppCreate(c fiber.Ctx) error {
	f := formFromRequest(c)
	f.New = true
	// /admin/apps/new is the form
	if f.ID == "new" {
		f.Errors = map[string]string{"id": "admin_apps.err_id_taken"}
		return r.renderAppForm(c, f, "")
	}
	id, secret, err := r.createOAuthClient(f.input(), r.username(c))
	if err != nil {
		return r.appFormError(c, f, err)
	}
	return r.renderAppSecret(c, appSecret{ID: id, Name: f.Name, Secret: secret, Kind: "create"})
}

func (r *Router) AdminAppUpdate(c fiber.Ctx) error {
	id := appID(c)
	f := formFromRequest(c)
	f.ID = id
	old, err := r.getManagedClient(id)
	if err != nil {
		slog.Error("Failed to read OAuth client", "client", id, "err", err)
		return r.renderAppForm(c, nil, TC(c, appErrorKey(err)))
	}
	cur := formFromClient(old)
	f.Kind, f.Title, f.Config, f.ConfigGroups = cur.Kind, cur.Title, cur.Config, cur.ConfigGroups
	in := f.input()
	narrow := !f.Config && narrows(resolveClientPolicy(old), in)
	f.Narrow = narrow
	if narrow && c.FormValue("confirm") != "1" {
		return r.renderAppForm(c, f, "")
	}
	if err := r.updateOAuthClient(id, in, r.username(c)); err != nil {
		return r.appFormError(c, f, err)
	}
	if narrow {
		// Hydra lists consent sessions per subject only, so the sweep
		// checks every user once. The periodic lease is held 9/10 of each
		// interval, so this takes its own claim.
		release, ok, err := r.lock.claim(appNarrowSweepKey, time.Hour)
		if ok {
			r.goBG(func() {
				defer release()
				r.consentSweep()
			})
		} else {
			slog.Warn("Consent sweep after narrowing skipped, another one is running; the periodic sweep catches up", "client", id, "err", err)
		}
	}
	return hxRedirect(c, "/admin/apps")
}

func (r *Router) appDangerError(c fiber.Ctx, err error) error {
	slog.Error("OAuth client change failed", "client", appID(c), "by", r.username(c), "err", err)
	return c.SendString(`<div class="alert alert-danger" role="alert">` + html.EscapeString(TC(c, appErrorKey(err))) + `</div>`)
}

func (r *Router) AdminAppRotate(c fiber.Ctx) error {
	id := appID(c)
	cl, err := r.getManagedClient(id)
	if err != nil {
		return r.appDangerError(c, err)
	}
	secret, err := r.rotateOAuthClientSecret(id, r.username(c))
	if err != nil {
		return r.appDangerError(c, err)
	}
	name := cl.GetClientName()
	if name == "" {
		name = id
	}
	// the button targets its alert slot; the secret page replaces the page
	c.Set("HX-Retarget", "#admin")
	c.Set("HX-Reswap", "innerHTML")
	return r.renderAppSecret(c, appSecret{ID: id, Name: name, Secret: secret, Kind: "rotate"})
}

func (r *Router) AdminAppDelete(c fiber.Ctx) error {
	if err := r.deleteOAuthClient(appID(c), r.username(c)); err != nil {
		return r.appDangerError(c, err)
	}
	return hxRedirect(c, "/admin/apps")
}
