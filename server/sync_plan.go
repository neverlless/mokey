package server

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
)

// syncSourceUser is an active Google Workspace user after source-side filtering.
type syncSourceUser struct {
	Email, GivenName, FamilyName, FullName string
	Groups                                 []string          // lowercased emails of mapped Google groups
	Attrs                                  map[string]string // rule attributes (syncRuleAttrs), lowercased
}

// syncUser is a source user with its derived FreeIPA uid.
type syncUser struct {
	UID string
	syncSourceUser
}

type syncMarkerKind string

const (
	syncMarkerSync   syncMarkerKind = "sync"   // sync disabled the account
	syncMarkerFound  syncMarkerKind = "found"  // found locked and gone from Google, cause unknown
	syncMarkerLegacy syncMarkerKind = "legacy" // google2ipa lock imported once
)

type syncMarker struct {
	Kind syncMarkerKind
	At   time.Time
	By   string
}

type syncIPAUser struct {
	UID, Email, GivenName, FamilyName, FullName string
	CN                                          string // "" when not read
	Managed, Locked, Preserved                  bool
	Expired                                     bool // krbPrincipalExpiration in the past
	Groups                                      []string
	Marker                                      *syncMarker // from storage, nil if none
}

// syncWhyGoogle in GroupWhy stands for group_mapping; rule names are never empty.
const syncWhyGoogle = ""

type syncUpdate struct {
	UID      string
	From, To syncSourceUser
}

type syncPlan struct {
	Create                  []syncUser
	Adopt, Unmanaged        []string
	Update                  []syncUpdate
	Enable, Disable, Delete []string
	AddGroups, RemoveGroups map[string][]string
	// GroupWhy names, per uid and changed group, the rules (and
	// syncWhyGoogle for group_mapping) that want an added group or owned a
	// removed one.
	GroupWhy map[string]map[string][]string
	// RuleMatches counts the Google users each rule matches, by rule name.
	RuleMatches   map[string]int
	NewMarkers    map[string]syncMarker // "found" markers to write
	ClearMarkers  []string              // unlocked accounts that still carry a marker, and found markers of BackInGoogle
	BackInGoogle  []string              // locked without a re-enable marker, present in Google
	Braked        bool                  // disable/delete and owned-group removals suppressed by the safety brake
	Conflicts     []string
	Skipped       []string
	NoMemberWrite []string // groups whose members the service account can't change
}

// withoutGroups drops the changes to groups the service account can't
// write: they would fail once per account. Without the managed group no
// account can be created or adopted.
func (p *syncPlan) withoutGroups(noWrite []string, managed string) {
	if len(noWrite) == 0 {
		return
	}
	p.NoMemberWrite = noWrite
	if slices.Contains(noWrite, managed) {
		for _, u := range p.Create {
			delete(p.AddGroups, u.UID)
		}
		for _, uid := range p.Adopt {
			delete(p.AddGroups, uid)
			delete(p.RemoveGroups, uid)
		}
		p.Create, p.Adopt = nil, nil
	}
	for _, m := range []map[string][]string{p.AddGroups, p.RemoveGroups} {
		for uid, gs := range m {
			gs = slices.DeleteFunc(slices.Clone(gs), func(g string) bool { return slices.Contains(noWrite, g) })
			if len(gs) == 0 {
				delete(m, uid)
			} else {
				m[uid] = gs
			}
		}
	}
}

func (p syncPlan) Empty() bool {
	return p.Changes()+len(p.NewMarkers)+len(p.ClearMarkers) == 0 && !p.Braked
}

// Changes counts account and group changes, one per group membership.
func (p syncPlan) Changes() int {
	n := len(p.Create) + len(p.Adopt) + len(p.Update) + len(p.Enable) + len(p.Disable) + len(p.Delete)
	for _, gs := range p.AddGroups {
		n += len(gs)
	}
	for _, gs := range p.RemoveGroups {
		n += len(gs)
	}
	return n
}

// FreeIPA's default uid pattern, lowercase only.
var syncUIDPattern = regexp.MustCompile(`^[a-z0-9_.][a-z0-9_.-]{0,252}[a-z0-9_.$-]?$`)

func syncDeriveUID(email, mode string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if mode == "email" {
		return strings.Replace(email, "@", ".", 1)
	}
	local, _, _ := strings.Cut(email, "@")
	return local
}

// syncResolve derives uids. Invalid or colliding uids are returned in
// skipped: they count as present in Google but are never modified.
func syncResolve(users []syncSourceUser, mode string, exclude []string, maxLen int) (resolved []syncUser, skipped []string, errs []error) {
	byUID := map[string][]syncSourceUser{}
	for _, u := range users {
		u.Email = strings.ToLower(strings.TrimSpace(u.Email))
		u.Groups = slices.Clone(u.Groups)
		for i, g := range u.Groups {
			u.Groups[i] = strings.ToLower(strings.TrimSpace(g))
		}
		uid := syncDeriveUID(u.Email, mode)
		if slices.Contains(exclude, uid) {
			continue
		}
		byUID[uid] = append(byUID[uid], u)
	}
	for _, uid := range slices.Sorted(maps.Keys(byUID)) {
		us := byUID[uid]
		switch {
		case !syncUIDPattern.MatchString(uid):
			skipped = append(skipped, uid)
			errs = append(errs, fmt.Errorf("skip %s: %q is not a valid FreeIPA uid", us[0].Email, uid))
		case len(uid) > maxLen:
			skipped = append(skipped, uid)
			errs = append(errs, fmt.Errorf("skip %s: uid %q is longer than %d characters (raise sync.max_username_length and ipa config-mod --maxusername)", us[0].Email, uid, maxLen))
		case len(us) > 1:
			skipped = append(skipped, uid)
			emails := make([]string, len(us))
			for i, u := range us {
				emails[i] = u.Email
			}
			errs = append(errs, fmt.Errorf("skip uid %q: derived from several Google users (%s)", uid, strings.Join(emails, ", ")))
		default:
			resolved = append(resolved, syncUser{UID: uid, syncSourceUser: us[0]})
		}
	}
	return resolved, skipped, errs
}

// syncBuild is pure: same inputs, same plan. It never performs I/O.
func syncBuild(users []syncUser, skipped []string, ipa map[string]syncIPAUser, cfg *syncConfig, now time.Time) syncPlan {
	p := syncPlan{
		AddGroups:    map[string][]string{},
		RemoveGroups: map[string][]string{},
		NewMarkers:   map[string]syncMarker{},
		GroupWhy:     map[string]map[string][]string{},
		RuleMatches:  map[string]int{},
		Skipped:      skipped,
	}
	excluded := cfg.ExcludeUsers
	mapped := cfg.mappedGroups()
	owned := cfg.ownedGroups()
	// owners: who owns each owned group, for the reason of a removal
	owners := map[string][]string{}
	for _, r := range cfg.Rules {
		p.RuleMatches[r.Name] = 0
		for _, g := range r.Groups {
			owners[g] = append(owners[g], r.Name)
		}
	}
	for _, g := range mapped {
		owners[g] = append(owners[g], syncWhyGoogle)
	}

	inGoogle := map[string]bool{}
	for _, uid := range skipped {
		inGoogle[uid] = true
	}
	for _, u := range users {
		inGoogle[u.UID] = true
		if slices.Contains(excluded, u.UID) {
			continue
		}
		for _, r := range cfg.Rules {
			if r.matches(u.Attrs) {
				p.RuleMatches[r.Name]++
			}
		}
		cur, exists := ipa[u.UID]
		switch {
		case !exists:
			p.Create = append(p.Create, u)
		case cur.Preserved:
			p.Conflicts = append(p.Conflicts, fmt.Sprintf("uid %s is a deleted (preserved) FreeIPA user; restore it with: ipa user-undel %s && ipa group-add-member %s --users=%s", u.UID, u.UID, cfg.ManagedGroup, u.UID))
			continue
		case !cur.Managed && !cfg.AdoptExisting:
			p.Unmanaged = append(p.Unmanaged, u.UID)
			continue
		case (!cur.Managed || cur.Locked) && !strings.EqualFold(cur.Email, u.Email):
			// Same uid, different person (reused local part or email, or a
			// mailless service account): never hand an old account, its
			// groups and password to someone else.
			if cur.Email == "" {
				p.Conflicts = append(p.Conflicts, fmt.Sprintf("uid %s has no email in FreeIPA but belongs to %s in Google; left alone", u.UID, u.Email))
			} else {
				p.Conflicts = append(p.Conflicts, fmt.Sprintf("uid %s belongs to %s in FreeIPA but to %s in Google; left alone", u.UID, cur.Email, u.Email))
			}
			continue
		case !cur.Managed:
			p.Adopt = append(p.Adopt, u.UID)
		default:
			from := syncSourceUser{Email: cur.Email, GivenName: cur.GivenName, FamilyName: cur.FamilyName, FullName: cur.FullName}
			to := syncSourceUser{Email: u.Email, GivenName: u.GivenName, FamilyName: u.FamilyName, FullName: u.FullName}
			if strings.EqualFold(from.Email, to.Email) {
				to.Email = from.Email
			}
			// FreeIPA requires the names; an empty source field never blanks one.
			for _, f := range [...]struct{ to, from *string }{{&to.GivenName, &from.GivenName}, {&to.FamilyName, &from.FamilyName}, {&to.FullName, &from.FullName}} {
				if *f.to == "" {
					*f.to = *f.from
				}
			}
			// syncUpdate rewrites cn too: a hand-edited cn is corrected
			cnDrift := cur.CN != "" && to.FullName != "" && cur.CN != to.FullName
			if cnDrift || from.Email != to.Email || from.GivenName != to.GivenName || from.FamilyName != to.FamilyName || from.FullName != to.FullName {
				p.Update = append(p.Update, syncUpdate{UID: u.UID, From: from, To: to})
			}
			if cur.Locked {
				// Only a lock sync itself made (or imported) is undone; an admin
				// block or a lock of unknown origin waits for a human.
				if cur.Marker != nil && (cur.Marker.Kind == syncMarkerSync || cur.Marker.Kind == syncMarkerLegacy) {
					p.Enable = append(p.Enable, u.UID)
				} else {
					p.BackInGoogle = append(p.BackInGoogle, u.UID)
				}
			}
		}

		// An account waiting for a human (locked, not enabled now) is not changed.
		if exists && cur.Locked && !slices.Contains(p.Enable, u.UID) {
			continue
		}

		ruled, why := ruleGroups(cfg.Rules, u.Attrs)
		want := append(slices.Clone(cfg.DefaultGroups), ruled...)
		for _, g := range u.Groups {
			for _, mg := range cfg.GroupMapping[g] {
				want = append(want, mg)
				if !slices.Contains(why[mg], syncWhyGoogle) {
					why[mg] = append(why[mg], syncWhyGoogle)
				}
			}
		}
		var add, remove []string
		for _, g := range want {
			if !slices.Contains(cur.Groups, g) && !slices.Contains(add, g) {
				add = append(add, g)
			}
		}
		for _, g := range cur.Groups {
			if slices.Contains(owned, g) && !slices.Contains(want, g) && !slices.Contains(remove, g) {
				remove = append(remove, g)
			}
		}
		slices.Sort(add)
		slices.Sort(remove)
		if len(add) > 0 {
			p.AddGroups[u.UID] = add
		}
		gw := map[string][]string{}
		for _, g := range add {
			if len(why[g]) > 0 {
				gw[g] = why[g]
			}
		}
		for _, g := range remove {
			gw[g] = owners[g]
		}
		if len(gw) > 0 {
			p.GroupWhy[u.UID] = gw
		}
		if len(remove) > 0 {
			p.RemoveGroups[u.UID] = remove
		}
	}

	active := 0
	for _, uid := range slices.Sorted(maps.Keys(ipa)) {
		cur := ipa[uid]
		if !cur.Managed || slices.Contains(excluded, uid) {
			continue
		}
		if !cur.Locked {
			active++
		}
		if inGoogle[uid] {
			continue
		}
		switch {
		case !cur.Locked:
			if cfg.Disable {
				p.Disable = append(p.Disable, uid)
			}
		case cur.Marker == nil:
			// Lock of unknown origin: start the delete clock now, never delete
			// on this run.
			p.NewMarkers[uid] = syncMarker{Kind: syncMarkerFound, At: now, By: "sync"}
		case cfg.DeleteAfter > 0 && now.Sub(cur.Marker.At) >= cfg.DeleteAfter:
			p.Delete = append(p.Delete, uid)
		}
	}

	// more than pct of active accounts, and never a single one
	trips := func(n int) bool { pct := cfg.MaxDisablePercent; return pct > 0 && n > 1 && n*100 > pct*active }
	if trips(len(p.Disable)) {
		// a suspect source starts no delete clocks either
		p.NewMarkers = map[string]syncMarker{}
		p.Braked = true
	}
	// counted in users who would lose an owned group, not in removals
	if trips(len(p.RemoveGroups)) {
		p.Braked = true
	}
	if p.Braked {
		p.Disable, p.Delete, p.RemoveGroups = nil, nil, map[string][]string{}
	}
	for _, uid := range slices.Sorted(maps.Keys(ipa)) {
		// A disable rewrites the marker itself; clearing it too would race.
		cur := ipa[uid]
		if cur.Marker == nil {
			continue
		}
		// a found marker of an account back in Google would make its next
		// departure an instant delete
		back := cur.Marker.Kind == syncMarkerFound && slices.Contains(p.BackInGoogle, uid)
		if (!cur.Locked && !slices.Contains(p.Disable, uid)) || back {
			p.ClearMarkers = append(p.ClearMarkers, uid)
		}
	}
	return p
}
