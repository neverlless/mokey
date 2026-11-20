package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
	hydra "github.com/ory/hydra-client-go/v26"
	"github.com/spf13/viper"
)

const appSecretTTL = 10 * time.Minute

var (
	appScopes        = []string{"openid", "profile", "email", "offline_access", "ssh"}
	appSecretPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

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

type appCopyRow struct{ Label, Value string }

// appSecret is the one-time secret page, kept for appSecretTTL.
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
		// shortcut: every group name in one find per render; switch to a
		// search endpoint if directories with many thousands of groups need it
		groups, err := r.adminClient.GroupFind(ipa.Options{"sizelimit": 0})
		if err != nil {
			slog.Error("Failed to list FreeIPA groups for the app form", "err", err)
		}
		names := make([]string, 0, len(groups))
		for _, g := range groups {
			names = append(names, g.Name)
		}
		vars["ap_groups"] = names
	}
	if c.Method() == fiber.MethodPost {
		return c.Render("admin-app-form.html", vars)
	}
	return c.Render("index.html", vars)
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
	cl, err := r.getManagedClient(c.Params("id"))
	if errors.Is(err, errClientNotFound) || errors.Is(err, errClientReadOnly) {
		return c.Status(fiber.StatusNotFound).SendString("")
	}
	if err != nil {
		slog.Error("Failed to read OAuth client", "client", c.Params("id"), "err", err)
		return r.renderAppForm(c, nil, TC(c, appErrorKey(err)))
	}
	return r.renderAppForm(c, formFromClient(cl), "")
}

// stashAppSecret keeps s for one view by this admin and returns the
// secret page URL. The key carries the username, so another admin's view
// finds nothing and can't use it up.
func (r *Router) stashAppSecret(c fiber.Ctx, s appSecret) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	k := hex.EncodeToString(b)
	raw, err := json.Marshal(s) // #nosec G117 -- held for one view, taken atomically, TTL appSecretTTL
	if err != nil {
		return "", err
	}
	if err := r.storage.Set(appSecretKey(r.username(c), k), raw, appSecretTTL); err != nil {
		return "", err
	}
	return "/admin/apps/" + s.ID + "/secret?k=" + k, nil
}

func appSecretKey(username, k string) string { return "app-secret-" + username + "-" + k }

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
	to, err := r.stashAppSecret(c, appSecret{ID: id, Name: f.Name, Secret: secret, Kind: "create"})
	if err != nil {
		slog.Error("Failed to keep the new OAuth client secret for its page", "client", id, "err", err)
		return hxRedirect(c, "/admin/apps/"+id)
	}
	return hxRedirect(c, to)
}

func (r *Router) AdminAppUpdate(c fiber.Ctx) error {
	id := c.Params("id")
	f := formFromRequest(c)
	f.ID = id
	old, err := r.getManagedClient(id)
	if err != nil {
		return r.appFormError(c, f, err)
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
		// checks every user once
		r.goBG(r.consentSweep)
	}
	return hxRedirect(c, "/admin/apps")
}

func (r *Router) appDangerError(c fiber.Ctx, err error) error {
	slog.Error("OAuth client change failed", "client", c.Params("id"), "by", r.username(c), "err", err)
	return c.SendString(`<div class="alert alert-danger" role="alert">` + html.EscapeString(TC(c, appErrorKey(err))) + `</div>`)
}

func (r *Router) AdminAppRotate(c fiber.Ctx) error {
	id := c.Params("id")
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
	to, err := r.stashAppSecret(c, appSecret{ID: id, Name: name, Secret: secret, Kind: "rotate"})
	if err != nil {
		slog.Error("Failed to keep the rotated OAuth client secret for its page", "client", id, "err", err)
		return r.appDangerError(c, err)
	}
	return hxRedirect(c, to)
}

func (r *Router) AdminAppDelete(c fiber.Ctx) error {
	if err := r.deleteOAuthClient(c.Params("id"), r.username(c)); err != nil {
		return r.appDangerError(c, err)
	}
	return hxRedirect(c, "/admin/apps")
}

func (r *Router) AdminAppSecret(c fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	id := c.Params("id")
	vars := r.appsPageVars(c, "secret")
	vars["ap_id"] = id
	if k := c.Query("k"); appSecretPattern.MatchString(k) {
		raw, err := r.lock.take(appSecretKey(r.username(c), k))
		if err != nil {
			slog.Error("Failed to read the one-time OAuth client secret", "client", id, "err", err)
			vars["ap_error"] = TC(c, "account.fatal_system_error")
		}
		var s appSecret
		if raw != nil && json.Unmarshal(raw, &s) == nil && s.ID == id {
			vars["ap_secret"] = &s
			rows := []appCopyRow{{TC(c, "admin_apps.client_id"), s.ID}}
			if s.Secret != "" {
				rows = append(rows, appCopyRow{TC(c, "admin_apps.client_secret"), s.Secret})
			}
			if u := r.hydraPublicURL; u != "" {
				vars["ap_public_url"] = true
				rows = append(rows,
					appCopyRow{TC(c, "admin_apps.issuer"), u + "/"},
					appCopyRow{TC(c, "admin_apps.discovery"), u + "/.well-known/openid-configuration"},
					appCopyRow{TC(c, "admin_apps.authorize"), u + "/oauth2/auth"},
					appCopyRow{TC(c, "admin_apps.token"), u + "/oauth2/token"},
				)
			}
			vars["ap_copy"] = rows
		}
	}
	return c.Render("index.html", vars)
}
