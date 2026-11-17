package server

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	ipa "github.com/neverlless/goipa"
)

// userSponsor returns the uid of the user's FreeIPA manager, or "".
func userSponsor(client *ipa.Client, uid string) (string, error) {
	u, err := client.UserShow(uid)
	if err != nil {
		return "", err
	}
	return sponsorUID(u.Manager), nil
}

// sponsorUID reduces a manager value, a bare uid or a DN, to the uid.
func sponsorUID(v string) string {
	if len(v) > 4 && strings.EqualFold(v[:4], "uid=") {
		v, _, _ = strings.Cut(v[4:], ",")
		return v
	}
	if strings.Contains(v, "=") {
		return ""
	}
	return v
}

// setUserSponsor sets the user's manager; "" clears it.
func setUserSponsor(client *ipa.Client, uid, sponsor string) error {
	return client.SetManager(uid, sponsor)
}

// setUserExpiry sets krbprincipalexpiration; the zero time clears it.
func setUserExpiry(client *ipa.Client, uid string, at time.Time) error {
	return client.SetPrincipalExpiration(uid, at)
}

// sponsoredBy lists the accounts whose manager is sponsor.
func sponsoredBy(client *ipa.Client, sponsor string) ([]*ipa.User, error) {
	return client.UserFind(ipa.Options{"manager": sponsor, "sizelimit": 0, "timelimit": 0})
}

// warnSelfServiceManager warns when a FreeIPA self-service rule lets users
// write their own manager: with renewal on, that is choosing their sponsor.
// FreeIPA's default "User Self service" rule does.
func (r *Router) warnSelfServiceManager() {
	if !r.lifecycle.on() || r.lifecycle.Renewal == 0 {
		return
	}
	rules, err := r.adminClient.SelfServiceFind(nil)
	if err != nil {
		slog.Warn("lifecycle: could not read the FreeIPA self-service rules to check that users can't change their own sponsor", "err", err)
		return
	}
	// FreeIPA always has self-service rules; none means they are hidden
	if len(rules) == 0 {
		slog.Warn("lifecycle: could not check that users can't change their own sponsor: mokey's role can't read the FreeIPA self-service rules; add the RBAC Readers privilege or check the rule by hand, see the account lifecycle guide")
		return
	}
	for _, rule := range rules {
		if len(rule.Permissions) > 0 && !slices.Contains(rule.Permissions, "write") {
			continue
		}
		if slices.ContainsFunc(rule.Attrs, func(a string) bool { return strings.EqualFold(a, "manager") }) {
			name := rule.Name
			slog.Warn("lifecycle: a FreeIPA self-service rule lets users change their own sponsor (manager); remove manager from it, see the account lifecycle guide",
				"rule", name,
				"fix", fmt.Sprintf(`ipa selfservice-show %q, then ipa selfservice-mod %q --attrs=... with the same attributes except manager`, name, name))
		}
	}
}
