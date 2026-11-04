package server

// Revokes Hydra consent sessions for OAuth clients a user's groups no longer
// admit them to. mokey never sets remember on consent, so new authorizations
// always pass the [[hydra.clients]] check; this closes the refresh tokens
// issued before the user lost the group.

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	ipa "github.com/neverlless/goipa"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// clientGroupsEnforced reports whether [[hydra.clients]] or default_deny
// restrict clients and the config parses. An invalid config already denies
// every consent; it must not also revoke every user's sessions.
func clientGroupsEnforced() bool {
	var policies []hydraClientPolicy
	if err := viper.UnmarshalKey("hydra.clients", &policies); err != nil {
		return false
	}
	for _, p := range policies {
		if p.ClientID == "" {
			return false
		}
	}
	return len(policies) > 0 || viper.GetBool("hydra.default_deny")
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
// client clientAllowed no longer admits them to; returns how many clients
func (r *Router) revokeDisallowedConsents(user *ipa.User) int {
	ids, err := r.consentClientIDs(user.Username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": user.Username,
			"err":      err,
		}).Error("Failed to list Hydra consent sessions")
		return 0
	}

	revoked := 0
	for _, id := range ids {
		if clientAllowed(id, user) {
			continue
		}
		if err := r.revokeConnectedApp(user.Username, id); err != nil {
			log.WithFields(log.Fields{
				"username": user.Username,
				"client":   id,
				"err":      err,
			}).Error("Failed to revoke Hydra consent session")
			continue
		}
		log.WithFields(log.Fields{
			"username": user.Username,
			"client":   id,
		}).Info("AUDIT OAuth2 consent revoked, user no longer in an allowed group")
		revoked++
	}
	return revoked
}

// revokeConsentsOf re-reads username after mokey removed them from a group
// and revokes what their groups no longer admit. Runs in r.goBG.
func (r *Router) revokeConsentsOf(username string) {
	if r.hydraClient == nil || !clientGroupsEnforced() {
		return
	}
	user, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Error("Failed to fetch user for Hydra consent revocation")
		return
	}
	r.revokeDisallowedConsents(user)
}

// consentSweepInterval is 0 when the sweep is off: no Hydra, no client
// restrictions, or hydra.consent_sweep_interval = "0"
func (r *Router) consentSweepInterval() time.Duration {
	if r.hydraClient == nil || !clientGroupsEnforced() {
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

	log.WithFields(log.Fields{
		"interval": interval,
	}).Info("Hydra consent sweep enabled")

	go func() {
		for {
			time.Sleep(interval)
			r.consentSweep()
		}
	}()
}

// consentSweep checks every FreeIPA user, since Hydra cannot list subjects.
// user_find folds nested groups into Groups, so memberOf still sees them.
func (r *Router) consentSweep() {
	users, err := r.adminClient.UserFind(ipa.Options{
		"sizelimit": 0,
		"timelimit": 0,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Hydra consent sweep failed to list users")
		return
	}

	revoked := 0
	for _, user := range users {
		revoked += r.revokeDisallowedConsents(user)
	}

	log.WithFields(log.Fields{
		"users":   len(users),
		"revoked": revoked,
	}).Info("Hydra consent sweep complete")
}
