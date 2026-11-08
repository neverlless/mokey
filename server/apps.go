package server

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v3"
	hydra "github.com/ory/hydra-client-go/v26"
	"github.com/spf13/viper"
)

const (
	appAvailable   = "available"
	appRequestable = "requestable"
	appPending     = "pending"
)

// catalogApp is what the Apps page may show about an OAuth client: never
// secrets or redirect URIs.
type catalogApp struct {
	ClientID string
	Name     string
	URI      string
	State    string
	// Group is the group to request, or the one with the pending request
	Group string
}

// listOAuthClients pages through Hydra's client list.
// shortcut: no cache, one admin API call per Apps page view; cache if
// deployments with many clients see it slow.
func (r *Router) listOAuthClients() ([]hydra.OAuth2Client, error) {
	var all []hydra.OAuth2Client
	token := ""
	for {
		req := r.hydraClient.OAuth2API.ListOAuth2Clients(context.Background()).PageSize(500)
		if token != "" {
			req = req.PageToken(token)
		}
		clients, resp, err := req.Execute()
		if err != nil {
			return nil, err
		}
		all = append(all, clients...)
		next := nextPageToken(resp)
		if next == "" || next == token {
			return all, nil
		}
		token = next
	}
}

// appCatalog lists the clients the user can use or ask for. Clients with
// no way in for this user, and machine-to-machine clients, are left out.
func (r *Router) appCatalog(c fiber.Ctx) ([]catalogApp, error) {
	user := r.user(c)

	clients, err := r.listOAuthClients()
	if err != nil {
		return nil, err
	}
	var policies []hydraClientPolicy
	if err := viper.UnmarshalKey("hydra.clients", &policies); err != nil {
		return nil, err
	}

	var managed map[string]*ipaGroup
	apps := []catalogApp{}
	for _, cl := range clients {
		grants := cl.GetGrantTypes()
		if len(grants) > 0 && !slices.Contains(grants, "authorization_code") {
			continue
		}

		app := catalogApp{ClientID: cl.GetClientId(), Name: cl.GetClientName(), URI: cl.GetClientUri()}
		if app.Name == "" {
			app.Name = app.ClientID
		}

		if clientAllowed(app.ClientID, user) {
			app.State = appAvailable
			apps = append(apps, app)
			continue
		}
		if !viper.GetBool("accounts.enable_groups") {
			continue
		}

		if managed == nil {
			groups, err := groupFindManaged(r.userClient(c))
			if err != nil {
				return nil, err
			}
			managed = map[string]*ipaGroup{}
			for _, g := range groups {
				managed[strings.ToLower(g.Name)] = g
			}
		}

		// first matching policy only, as clientAllowed does; the first
		// requestable group in config order wins unless one is pending
		if i := slices.IndexFunc(policies, func(p hydraClientPolicy) bool { return p.ClientID == app.ClientID }); i >= 0 {
			for _, want := range policies[i].Groups {
				g := managed[strings.ToLower(want)]
				if g == nil {
					continue
				}
				if r.hasJoinRequest(g.Name, user.Username) {
					app.State, app.Group = appPending, g.Name
					break
				}
				if app.State == "" {
					app.State, app.Group = appRequestable, g.Name
				}
			}
		}
		if app.State != "" {
			apps = append(apps, app)
		}
	}

	sort.SliceStable(apps, func(i, j int) bool { return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name) })
	return apps, nil
}

func (r *Router) hasJoinRequest(group, username string) bool {
	for _, req := range r.loadGroupRequests(group) {
		if req.Username == username && req.Type == groupRequestJoin {
			return true
		}
	}
	return false
}

func (r *Router) appsVars(c fiber.Ctx, vars fiber.Map) {
	apps, err := r.appCatalog(c)
	if err != nil {
		slog.Error("Failed to build the app catalog",
			"username", r.username(c),
			"err", err,
		)
		vars["apps_error"] = true
		return
	}
	vars["apps"] = apps
}

// AppRequest asks for access to a client by queueing a join request for
// the group the catalog picked; the group never comes from the form.
func (r *Router) AppRequest(c fiber.Ctx) error {
	apps, err := r.appCatalog(c)
	if err != nil {
		slog.Error("Failed to build the app catalog",
			"username", r.username(c),
			"err", err,
		)
		return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "account.fatal_system_error"))
	}

	i := slices.IndexFunc(apps, func(a catalogApp) bool {
		return a.ClientID == c.FormValue("client") && a.State == appRequestable
	})
	if i < 0 {
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, "apps.not_requestable"))
	}
	// no picker on the Apps page: the longest grant offered, or permanent
	duration := ""
	if ds, permanent := r.groupExpiry.Offered(apps[i].Group); !permanent && len(ds) > 0 {
		duration = ds[len(ds)-1].String()
	}
	if ferr := r.requestJoin(c, apps[i].Group, duration); ferr != nil {
		return c.Status(ferr.Code).SendString(ferr.Message)
	}

	vars := fiber.Map{"user": r.user(c)}
	r.appsVars(c, vars)
	return c.Render("apps-list.html", vars)
}
