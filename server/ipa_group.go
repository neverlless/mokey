// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"github.com/tidwall/gjson"
	ipa "github.com/ubccr/goipa"
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
	res, err := ipaSessionRPC(client, "group_add_member", []string{cn}, map[string]interface{}{"user": uid})
	if err == nil && res != nil {
		if f := gjson.GetBytes(res.Result.Data, "failed.member.user"); f.Exists() && len(f.Array()) > 0 {
			return &ipa.IpaError{Code: 2100, Message: f.Array()[0].String()}
		}
	}
	return err
}
