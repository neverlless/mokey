package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	ipa "github.com/neverlless/goipa"
)

const syncMarkerPrefix = "sync-marker-"

// syncLoadIPA reads the managed accounts and the requested uids that are
// not managed. Memberships come from group_show, which lists direct
// members only: user_find with all merges indirect groups into
// memberof_group. Groups holds only the managed, default and mapped groups.
func (r *Router) syncLoadIPA(ctx context.Context, cfg *syncConfig, uids []string, now time.Time) (map[string]syncIPAUser, error) {
	members := map[string][]string{}
	for _, g := range slices.Compact(slices.Sorted(slices.Values(append(append([]string{cfg.ManagedGroup}, cfg.DefaultGroups...), cfg.mappedGroups()...)))) {
		grp, err := r.adminClient.GroupShow(g)
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", g, err)
		}
		for _, uid := range grp.Users {
			members[uid] = append(members[uid], g)
		}
	}

	out := map[string]syncIPAUser{}
	for _, preserved := range []bool{false, true} {
		entries, err := ipa.FindEntries(ctx, r.adminClient, "user_find", nil,
			ipa.Options{"all": true, "no_members": true, "preserved": preserved, "sizelimit": 0, "timelimit": 0}, 0)
		if err != nil {
			return nil, fmt.Errorf("user_find: %w", err)
		}
		for _, e := range entries {
			uid := e.Str("uid")
			managed := !preserved && slices.Contains(members[uid], cfg.ManagedGroup)
			if !managed && !slices.Contains(uids, uid) {
				continue
			}
			exp := e.Time("krbprincipalexpiration")
			u := syncIPAUser{
				UID:        uid,
				Email:      e.Str("mail"),
				GivenName:  e.Str("givenname"),
				FamilyName: e.Str("sn"),
				FullName:   e.Str("displayname"),
				Managed:    managed,
				Locked:     e.Bool("nsaccountlock"),
				Preserved:  preserved,
				Expired:    !exp.IsZero() && exp.Before(now),
				Groups:     members[uid],
			}
			if u.Marker, err = r.syncGetMarker(uid); err != nil {
				return nil, err
			}
			out[uid] = u
		}
	}
	return out, nil
}

// syncCreate adds the account without a password: the user sets one
// through the welcome link.
func (r *Router) syncCreate(u syncUser, cfg *syncConfig) error {
	if _, err := r.adminClient.UserAdd(&ipa.User{
		Username:    u.UID,
		First:       u.GivenName,
		Last:        u.FamilyName,
		DisplayName: u.FullName,
		Email:       u.Email,
	}, false); err != nil {
		return err
	}
	if err := r.syncGroups(u.UID, []string{cfg.ManagedGroup}, nil); err != nil {
		return fmt.Errorf("created %s, not managed: %w", u.UID, err)
	}
	if err := r.syncSetCN(u.UID, u.FullName); err != nil {
		return fmt.Errorf("created %s, full name not set: %w", u.UID, err)
	}
	return nil
}

// syncWelcome runs after a complete create; a failure is a run error for the
// account, the account stays.
func (r *Router) syncWelcome(uid string, ttl time.Duration) error {
	user, err := r.adminClient.UserShow(uid)
	if err != nil {
		return err
	}
	return r.emailer.SendSyncWelcomeEmail(user, ttl)
}

// syncSetCN writes cn as google2ipa did; goipa's User has no cn field.
func (r *Router) syncSetCN(uid, cn string) error {
	if cn == "" {
		return nil
	}
	_, err := r.adminClient.Modify("user_mod", uid).Set("cn", cn).Run(context.Background())
	if errors.Is(err, ipa.ErrEmptyModlist) {
		return nil
	}
	return err
}

func (r *Router) syncUpdate(u syncUpdate) error {
	cur, err := r.adminClient.UserShow(u.UID)
	if err != nil {
		return err
	}
	cur.Email, cur.First, cur.Last, cur.DisplayName = u.To.Email, u.To.GivenName, u.To.FamilyName, u.To.FullName
	if len(cur.Emails) > 0 {
		cur.Emails[0] = u.To.Email
	}
	if _, err := r.adminClient.UserMod(cur); err != nil {
		return err
	}
	return r.syncSetCN(u.UID, u.To.FullName)
}

// syncDisable writes the marker first: a lock sync made but didn't record
// would never be undone by sync. A marker left on an account that stayed
// unlocked is cleared by a later run, but one on an account someone else
// locked meanwhile would let sync unlock it, so that one is rolled back.
func (r *Router) syncDisable(uid string, now time.Time, by string) error {
	prev, err := r.syncGetMarker(uid)
	if err != nil {
		return err
	}
	if err := r.syncSetMarker(uid, syncMarker{Kind: syncMarkerSync, At: now, By: by}); err != nil {
		return err
	}
	err = r.adminClient.UserDisable(uid)
	if err == nil {
		r.faRevokeUser(uid)
	}
	if !errors.Is(err, &ipa.IpaError{Code: ipa.CodeAlreadyInactive}) {
		return err
	}
	if prev == nil {
		return errors.Join(err, r.syncClearMarker(uid))
	}
	return errors.Join(err, r.syncSetMarker(uid, *prev))
}

// syncEnable clears krbPrincipalExpiration only for a google2ipa lock,
// which wrote its lock time there; otherwise it is a sponsor's expiry.
func (r *Router) syncEnable(uid string, m syncMarker) error {
	if m.Kind == syncMarkerLegacy {
		if err := setUserExpiry(r.adminClient, uid, time.Time{}); err != nil {
			return err
		}
	}
	if err := r.adminClient.UserEnable(uid); err != nil {
		return err
	}
	return r.syncClearMarker(uid)
}

func (r *Router) syncDelete(uid string, preserve bool) error {
	if err := r.adminClient.UserDelete(preserve, true, uid); err != nil {
		return err
	}
	return r.syncClearMarker(uid)
}

func (r *Router) syncGroups(uid string, add, remove []string) error {
	for _, g := range slices.Compact(slices.Sorted(slices.Values(add))) {
		if err := groupAddMember(r.adminClient, g, uid); err != nil {
			return fmt.Errorf("add %s to %s: %w", uid, g, err)
		}
	}
	for _, g := range slices.Compact(slices.Sorted(slices.Values(remove))) {
		if err := groupRemoveMember(r.adminClient, g, uid); err != nil {
			return fmt.Errorf("remove %s from %s: %w", uid, g, err)
		}
	}
	if len(remove) > 0 {
		r.revokeConsentsOf(uid)
	}
	return nil
}

func (r *Router) syncSetMarker(uid string, m syncMarker) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return r.storage.Set(syncMarkerPrefix+uid, b, 0)
}

// syncGetMarker returns nil when the account has no marker.
func (r *Router) syncGetMarker(uid string) (*syncMarker, error) {
	b, err := r.storage.Get(syncMarkerPrefix + uid)
	if err != nil || b == nil {
		return nil, err
	}
	var m syncMarker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("marker of %s: %w", uid, err)
	}
	return &m, nil
}

// syncClearMarker succeeds when there is no marker.
func (r *Router) syncClearMarker(uid string) error {
	return r.storage.Delete(syncMarkerPrefix + uid)
}
