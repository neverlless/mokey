package server

import (
	"encoding/json"
	"time"
)

const timedMembersKey = "timedmembers"

type TimedMembership struct {
	Group     string    `json:"group"`
	Username  string    `json:"username"`
	Until     time.Time `json:"until"`
	GrantedBy string    `json:"granted_by"`
	GrantedAt time.Time `json:"granted_at"`
}

func (r *Router) loadTimedMembers() ([]TimedMembership, error) {
	raw, err := r.storage.Get(timedMembersKey)
	if err != nil || raw == nil {
		return nil, err
	}
	var all []TimedMembership
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, err
	}
	return all, nil
}

// no TTL: the record outlives every session and must not expire on its own
func (r *Router) saveTimedMembers(all []TimedMembership) error {
	raw, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return r.storage.Set(timedMembersKey, raw, 0)
}

// modifyTimedMembers is a load-modify-save under the strict lock; fn returns
// the new list
func (r *Router) modifyTimedMembers(fn func([]TimedMembership) []TimedMembership) error {
	release, err := r.lock.holdStrict(timedMembersKey)
	if err != nil {
		return err
	}
	defer release()

	all, err := r.loadTimedMembers()
	if err != nil {
		return err
	}
	return r.saveTimedMembers(fn(all))
}

func (r *Router) putTimedMember(m TimedMembership) error {
	return r.modifyTimedMembers(func(all []TimedMembership) []TimedMembership {
		for i := range all {
			if all[i].Group == m.Group && all[i].Username == m.Username {
				all[i] = m
				return all
			}
		}
		return append(all, m)
	})
}

func (r *Router) dropTimedMember(group, username string) error {
	return r.modifyTimedMembers(func(all []TimedMembership) []TimedMembership {
		kept := all[:0]
		for _, m := range all {
			if m.Group != group || m.Username != username {
				kept = append(kept, m)
			}
		}
		return kept
	})
}

// dropTimedMemberIf drops the record only while it still ends at until, so a
// renewal or new grant written since it was read survives
func (r *Router) dropTimedMemberIf(group, username string, until time.Time) (dropped bool, err error) {
	err = r.modifyTimedMembers(func(all []TimedMembership) []TimedMembership {
		dropped = false
		kept := all[:0]
		for _, m := range all {
			if m.Group == group && m.Username == username && m.Until.Equal(until) {
				dropped = true
				continue
			}
			kept = append(kept, m)
		}
		return kept
	})
	return dropped && err == nil, err
}

func (r *Router) timedMember(group, username string) (*TimedMembership, error) {
	all, err := r.loadTimedMembers()
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.Group == group && m.Username == username {
			return &m, nil
		}
	}
	return nil, nil
}
