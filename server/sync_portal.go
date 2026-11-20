package server

import (
	"slices"
	"strings"

	ipa "github.com/neverlless/goipa"
)

// syncManaged reads the groups already on the loaded user: no FreeIPA call.
func (r *Router) syncManaged(u *ipa.User) bool {
	return r.sync.on() && u.HasGroup(r.sync.ManagedGroup)
}

// syncMapped is true for groups whose membership the source owns.
func (r *Router) syncMapped(group string) bool {
	return slices.Contains(r.sync.ownedGroups(), group)
}

// syncDomain is true when the address belongs to a Google Workspace domain.
func (r *Router) syncDomain(email string) bool {
	if !r.sync.on() {
		return false
	}
	i := strings.LastIndex(email, "@")
	return i >= 0 && slices.Contains(r.sync.Google.Domains, strings.ToLower(strings.TrimSpace(email[i+1:])))
}
