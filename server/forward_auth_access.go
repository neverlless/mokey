package server

import (
	"slices"
	"strings"

	ipa "github.com/neverlless/goipa"
	"github.com/spf13/viper"
)

type faDecision struct {
	Allowed bool
	Reason  string
	User    *ipa.User
	Groups  []string
}

// faAccess applies the forward-auth access rules. A missing user is a
// denial; any other FreeIPA error is returned so the caller fails closed.
func (r *Router) faAccess(username string, app faApp) (faDecision, error) {
	if isBlocked(username) {
		return faDecision{Reason: "blocked"}, nil
	}
	user, err := r.adminClient.UserShow(username)
	if err != nil {
		if entryGone(err) {
			return faDecision{Reason: "no_user"}, nil
		}
		return faDecision{}, err
	}
	groups := memberOf(user)
	deny := func(reason string) (faDecision, error) {
		return faDecision{Reason: reason, User: user, Groups: groups}, nil
	}
	switch {
	case user.Locked:
		return deny("disabled")
	case viper.GetBool("accounts.require_mfa") && !user.OTPOnly():
		return deny("mfa_required")
	}
	if len(app.Groups) > 0 && !slices.ContainsFunc(app.Groups, func(want string) bool {
		return slices.ContainsFunc(groups, func(g string) bool { return strings.EqualFold(g, want) })
	}) {
		return deny("not_in_group")
	}
	if app.HBACService != "" {
		host := app.HBACHost
		if host == "" {
			host = app.Host
		}
		res, err := hbacTest(r.adminClient, username, host, app.HBACService)
		if err != nil {
			return faDecision{}, err
		}
		if !res.Granted {
			return deny("hbac_denied")
		}
	}
	return faDecision{Allowed: true, User: user, Groups: groups}, nil
}
