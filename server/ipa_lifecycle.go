package server

import (
	"context"
	"errors"
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
