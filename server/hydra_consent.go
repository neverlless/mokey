package server

// Revokes Hydra consent sessions for OAuth clients a user's groups no longer
// admit them to. mokey never sets remember on consent, so new authorizations
// always pass the client access check; this closes the refresh tokens
// issued before the user lost the group.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	ipa "github.com/neverlless/goipa"
	hydra "github.com/ory/hydra-client-go/v26"
	"github.com/spf13/viper"
)

// clientPolicies resolves every Hydra client once. An invalid
// [[hydra.clients]] is an error: it already denies every consent and must
// not also revoke every user's sessions.
func (r *Router) clientPolicies() (map[string]clientPolicy, error) {
	config, err := configPolicies()
	if err != nil {
		return nil, fmt.Errorf("invalid hydra.clients config: %w", err)
	}
	clients, err := r.listOAuthClients()
	if err != nil {
		return nil, err
	}
	policies := make(map[string]clientPolicy, len(clients)+len(config))
	for _, p := range config {
		if _, ok := policies[p.ClientID]; !ok {
			policies[p.ClientID] = clientPolicy{Source: "config", Groups: p.Groups}
		}
	}
	for i := range clients {
		if _, ok := policies[clients[i].GetClientId()]; !ok {
			policies[clients[i].GetClientId()] = resolveClientPolicy(&clients[i])
		}
	}
	return policies, nil
}

func anyRestricted(policies map[string]clientPolicy) bool {
	if viper.GetBool("hydra.default_deny") {
		return true
	}
	for _, p := range policies {
		if !p.All {
			return true
		}
	}
	return false
}

// nextPageToken returns the page_token of the rel="next" Link Hydra sends
// when more pages follow, "" on the last page
func nextPageToken(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	for _, link := range strings.Split(strings.Join(resp.Header.Values("Link"), ","), ",") {
		target, params, ok := strings.Cut(link, ";")
		if !ok || !strings.Contains(params, `rel="next"`) {
			continue
		}
		u, err := url.Parse(strings.Trim(strings.TrimSpace(target), "<>"))
		if err != nil {
			return ""
		}
		return u.Query().Get("page_token")
	}
	return ""
}

// consentClientIDs lists the distinct clients username holds consent
// sessions for, across all pages
func (r *Router) consentClientIDs(username string) ([]string, error) {
	ids := []string{}
	token := ""
	for {
		req := r.hydraClient.OAuth2API.ListOAuth2ConsentSessions(context.Background()).Subject(username)
		if token != "" {
			req = req.PageToken(token)
		}
		sessions, resp, err := req.Execute()
		if err != nil {
			return nil, err
		}
		for _, s := range sessions {
			if cr := s.ConsentRequest; cr != nil && cr.Client != nil {
				if id := cr.Client.GetClientId(); !slices.Contains(ids, id) {
					ids = append(ids, id)
				}
			}
		}
		next := nextPageToken(resp)
		if next == "" || next == token {
			return ids, nil
		}
		token = next
	}
}

// revokeDisallowedConsents revokes the user's consent sessions for every
// client whose policy no longer admits them; returns how many clients
func (r *Router) revokeDisallowedConsents(user *ipa.User) int {
	policies, err := r.clientPolicies()
	if err != nil {
		slog.Error("Failed to resolve OAuth client access, not revoking consents",
			"username", user.Username,
			"err", err,
		)
		return 0
	}
	if !anyRestricted(policies) {
		return 0
	}
	return r.revokeDisallowed(user, policies)
}

func (r *Router) revokeDisallowed(user *ipa.User, policies map[string]clientPolicy) int {
	ids, err := r.consentClientIDs(user.Username)
	if err != nil {
		slog.Error("Failed to list Hydra consent sessions",
			"username", user.Username,
			"err", err,
		)
		return 0
	}

	revoked := 0
	for _, id := range ids {
		p, ok := policies[id]
		if !ok {
			p = resolveClientPolicy(&hydra.OAuth2Client{ClientId: &id})
		}
		if policyAllows(p, user) {
			continue
		}
		if err := r.revokeConnectedApp(user.Username, id); err != nil {
			slog.Error("Failed to revoke Hydra consent session",
				"username", user.Username,
				"client", id,
				"err", err,
			)
			continue
		}
		slog.Info("AUDIT OAuth2 consent revoked, user no longer in an allowed group",
			"username", user.Username,
			"client", id,
		)
		revoked++
	}
	return revoked
}

// revokeAllConsents ends every OAuth consent of an account that is gone.
func (r *Router) revokeAllConsents(username string) {
	if r.hydraClient == nil {
		return
	}
	if _, err := r.hydraClient.OAuth2API.RevokeOAuth2ConsentSessions(context.Background()).Subject(username).All(true).Execute(); err != nil {
		slog.Error("Failed to revoke Hydra consents", "username", username, "err", err)
	}
}

// revokeConsentsOf re-reads username after mokey removed them from a group
// and revokes what their groups no longer admit. Runs in r.goBG.
func (r *Router) revokeConsentsOf(username string) {
	if r.hydraClient == nil {
		return
	}
	user, err := r.adminClient.UserShow(username)
	if err != nil {
		slog.Error("Failed to fetch user for Hydra consent revocation",
			"username", username,
			"err", err,
		)
		return
	}
	r.revokeDisallowedConsents(user)
}

// consentSweepInterval is 0 when the sweep is off: no Hydra, or
// hydra.consent_sweep_interval = "0"
func (r *Router) consentSweepInterval() time.Duration {
	if r.hydraClient == nil {
		return 0
	}
	return viper.GetDuration("hydra.consent_sweep_interval")
}

// StartConsentSweep periodically catches group removals made directly in
// FreeIPA. Runs for the lifetime of the process.
func (r *Router) StartConsentSweep() {
	interval := r.consentSweepInterval()
	if interval <= 0 {
		return
	}

	slog.Info("Hydra consent sweep enabled",
		"interval", interval,
	)

	go func() {
		for {
			time.Sleep(interval)
			if r.lock.lease("consent-sweep", interval) {
				r.consentSweep()
			}
		}
	}()
}

// consentSweep checks every FreeIPA user, since Hydra cannot list subjects.
// user_find folds nested groups into Groups, so memberOf still sees them.
func (r *Router) consentSweep() {
	policies, err := r.clientPolicies()
	if err != nil {
		slog.Error("Hydra consent sweep failed to resolve OAuth client access",
			"err", err,
		)
		return
	}
	if !anyRestricted(policies) {
		return
	}

	users, err := r.adminClient.UserFind(ipa.Options{
		"sizelimit": 0,
		"timelimit": 0,
	})
	if err != nil {
		slog.Error("Hydra consent sweep failed to list users",
			"err", err,
		)
		return
	}

	revoked := 0
	for _, user := range users {
		revoked += r.revokeDisallowed(user, policies)
	}

	slog.Info("Hydra consent sweep complete",
		"users", len(users),
		"revoked", revoked,
	)
}
