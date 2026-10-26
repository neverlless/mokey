// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"errors"

	ipa "github.com/neverlless/goipa"
)

// Reads run under any session; group_add_member runs under the SPONSOR's
// session so FreeIPA enforces member-manager rights server-side — the admin
// client never mutates group membership.

type ipaGroup struct {
	Name          string
	Description   string
	Members       []string
	ManagerUsers  []string
	ManagerGroups []string
}

func groupFrom(g *ipa.Group) *ipaGroup {
	return &ipaGroup{
		Name:          g.Name,
		Description:   g.Description,
		Members:       g.Users,
		ManagerUsers:  g.ManagerUsers,
		ManagerGroups: g.ManagerGroups,
	}
}

// Managed returns true when the group has at least one member manager —
// the convention that makes it joinable through mokey.
func (g *ipaGroup) Managed() bool {
	return len(g.ManagerUsers) > 0 || len(g.ManagerGroups) > 0
}

// groupFindManaged lists groups that have member managers. One call
// serves the whole /groups render; sections are computed client-side.
func groupFindManaged(client *ipa.Client) ([]*ipaGroup, error) {
	found, err := client.GroupFind(ipa.Options{"sizelimit": 500})
	if err != nil {
		return nil, err
	}
	groups := []*ipaGroup{}
	for _, rec := range found {
		if g := groupFrom(rec); g.Managed() {
			groups = append(groups, g)
		}
	}
	return groups, nil
}

func groupShow(client *ipa.Client, cn string) (*ipaGroup, error) {
	g, err := client.GroupShow(cn)
	if err != nil {
		return nil, err
	}
	return groupFrom(g), nil
}

func groupAddMember(client *ipa.Client, cn, uid string) error {
	_, err := client.GroupAddMember(cn, []string{uid}, nil)
	return memberRefusal(err, "This entry is already a member")
}

func groupRemoveMember(client *ipa.Client, cn, uid string) error {
	_, err := client.GroupRemoveMember(cn, []string{uid}, nil)
	return memberRefusal(err, "This entry is not a member")
}

// memberRefusal reports FreeIPA's per-member refusals, which come with
// HTTP 200 and no error. Already being in the wanted state is not a
// failure.
func memberRefusal(err error, alreadyDone string) error {
	var merr *ipa.MemberError
	if !errors.As(err, &merr) {
		return err
	}
	for _, f := range merr.Failures {
		if f.Message != alreadyDone {
			return &ipa.IpaError{Code: 2100, Message: f.Message}
		}
	}
	return nil
}
