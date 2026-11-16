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
	if rest, ok := strings.CutPrefix(v, "uid="); ok {
		v, _, _ = strings.Cut(rest, ",")
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
	v := ""
	if !at.IsZero() {
		v = at.UTC().Format(ipa.IpaDatetimeFormat)
	}
	return userMod(client, uid, ipa.Options{"krbprincipalexpiration": v})
}

// sponsoredBy lists the accounts whose manager is sponsor.
func sponsoredBy(client *ipa.Client, sponsor string) ([]*ipa.User, error) {
	return client.UserFind(ipa.Options{"manager": sponsor})
}
