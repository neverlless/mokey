package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	ipa "github.com/neverlless/goipa"
)

// shortcut: raw user_show/user_mod until goipa exposes manager and
// krbprincipalexpiration on User (see the issue in the task report).

// userSponsor returns the uid of the user's FreeIPA manager, or "".
func userSponsor(client *ipa.Client, uid string) (string, error) {
	e, _, err := ipa.Call[ipa.Entry](context.Background(), client, "user_show", []string{uid}, ipa.Options{"all": true})
	if err != nil {
		return "", err
	}
	return sponsorUID(e.Str("manager")), nil
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

func userMod(client *ipa.Client, uid string, opts ipa.Options) error {
	_, err := client.RPC("user_mod", []string{uid}, opts)
	if errors.Is(err, ipa.ErrEmptyModlist) {
		return nil
	}
	return err
}

// setUserSponsor sets the user's manager; "" clears it.
func setUserSponsor(client *ipa.Client, uid, sponsor string) error {
	return userMod(client, uid, ipa.Options{"manager": sponsor})
}

// setUserExpiry sets krbprincipalexpiration; the zero time clears it.
func setUserExpiry(client *ipa.Client, uid string, at time.Time) error {
	var v any = ""
	if !at.IsZero() {
		v = map[string]string{"__datetime__": at.UTC().Format(ipa.IpaDatetimeFormat)}
	}
	return userMod(client, uid, ipa.Options{"krbprincipalexpiration": v})
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
	// shortcut: raw selfservice_find until goipa has SelfServiceFind
	rules, err := ipa.FindEntries(context.Background(), r.adminClient, "selfservice_find", nil, ipa.Options{"all": true}, 0)
	if err != nil {
		slog.Warn("lifecycle: could not read the FreeIPA self-service rules to check that users can't change their own sponsor", "err", err)
		return
	}
	// FreeIPA always has self-service rules; none means they are hidden
	if len(rules) == 0 {
		slog.Warn("lifecycle: could not check that users can't change their own sponsor: mokey's role can't read the FreeIPA self-service rules; add the RBAC Readers privilege or check the rule by hand, see the account lifecycle guide")
		return
	}
	for _, e := range rules {
		perms := e.Strs("permissions")
		if len(perms) > 0 && !slices.Contains(perms, "write") {
			continue
		}
		if slices.ContainsFunc(e.Strs("attrs"), func(a string) bool { return strings.EqualFold(a, "manager") }) {
			name := e.Str("aciname")
			slog.Warn("lifecycle: a FreeIPA self-service rule lets users change their own sponsor (manager); remove manager from it, see the account lifecycle guide",
				"rule", name,
				"fix", fmt.Sprintf(`ipa selfservice-show %q, then ipa selfservice-mod %q --attrs=... with the same attributes except manager`, name, name))
		}
	}
}
