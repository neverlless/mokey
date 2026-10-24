// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	ipa "github.com/neverlless/goipa"
	"github.com/tidwall/gjson"
)

// goipa has no group support, so the group_* commands go through the
// direct session RPC (see ipa_passkey.go). Reads run under any session;
// group_add_member runs under the SPONSOR's session so FreeIPA enforces
// member-manager rights server-side — the admin client never mutates
// group membership.

type ipaGroup struct {
	Name          string
	Description   string
	Members       []string
	ManagerUsers  []string
	ManagerGroups []string
}

func groupFromRecord(rec gjson.Result) *ipaGroup {
	g := &ipaGroup{
		Name:        rec.Get("cn.0").String(),
		Description: rec.Get("description.0").String(),
	}
	for _, v := range rec.Get("member_user").Array() {
		g.Members = append(g.Members, v.String())
	}
	for _, v := range rec.Get("membermanager_user").Array() {
		g.ManagerUsers = append(g.ManagerUsers, v.String())
	}
	for _, v := range rec.Get("membermanager_group").Array() {
		g.ManagerGroups = append(g.ManagerGroups, v.String())
	}
	return g
}

// Managed returns true when the group has at least one member manager —
// the convention that makes it joinable through mokey.
func (g *ipaGroup) Managed() bool {
	return len(g.ManagerUsers) > 0 || len(g.ManagerGroups) > 0
}

// groupFindManaged lists groups that have member managers. One call
// serves the whole /groups render; sections are computed client-side.
func groupFindManaged(client *ipa.Client) ([]*ipaGroup, error) {
	res, err := ipaSessionRPC(client, "group_find", []string{}, map[string]interface{}{
		"all":       true,
		"sizelimit": 500,
	})
	if err != nil {
		return nil, err
	}
	groups := []*ipaGroup{}
	for _, rec := range gjson.ParseBytes(res.Result.Data).Array() {
		if g := groupFromRecord(rec); g.Managed() {
			groups = append(groups, g)
		}
	}
	return groups, nil
}

func groupShow(client *ipa.Client, cn string) (*ipaGroup, error) {
	res, err := ipaSessionRPC(client, "group_show", []string{cn}, map[string]interface{}{"all": true})
	if err != nil {
		return nil, err
	}
	return groupFromRecord(gjson.ParseBytes(res.Result.Data)), nil
}

func groupAddMember(client *ipa.Client, cn, uid string) error {
	return groupChangeMember(client, "group_add_member", cn, uid, "This entry is already a member")
}

func groupRemoveMember(client *ipa.Client, cn, uid string) error {
	return groupChangeMember(client, "group_remove_member", cn, uid, "This entry is not a member")
}

// groupChangeMember reports FreeIPA's per-member refusals, which come with
// HTTP 200 and no error in result.failed. Already being in the wanted
// state is not a failure.
func groupChangeMember(client *ipa.Client, method, cn, uid, alreadyDone string) error {
	res, err := ipaSessionResult(client, method, []string{cn}, map[string]interface{}{"user": uid})
	if err != nil {
		return err
	}
	for _, f := range res.Get("failed.member.user").Array() {
		if msg := f.Get("1").String(); msg != alreadyDone {
			return &ipa.IpaError{Code: 2100, Message: msg}
		}
	}
	return nil
}
