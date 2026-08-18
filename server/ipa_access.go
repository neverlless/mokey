// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"strings"

	"github.com/tidwall/gjson"
	ipa "github.com/ubccr/goipa"
)

// goipa has no HBAC/sudo support, so hbacrule_find / sudorule_find /
// hbactest go through the direct session RPC (see ipa_passkey.go). All
// three are readable/runnable by any authenticated user — "System: Read
// HBAC Rules" and "System: Read Sudo Rules" ship with bind rule "all",
// so the USER's session client is used and the admin client stays out
// of this page entirely.

type hbacRule struct {
	Name             string
	Description      string
	Enabled          bool
	UserCategory     string
	HostCategory     string
	ServiceCategory  string
	MemberUsers      []string
	MemberGroups     []string
	MemberHosts      []string
	MemberHostgroups []string
	MemberServices   []string
}

type sudoRule struct {
	Name             string
	Description      string
	Enabled          bool
	UserCategory     string
	HostCategory     string
	CmdCategory      string
	MemberUsers      []string
	MemberGroups     []string
	MemberHosts      []string
	MemberHostgroups []string
	AllowCommands    []string
	DenyCommands     []string
	RunAsUsers       []string
	RunAsGroups      []string
}

type hbacTestResult struct {
	Granted    bool
	Matched    []string
	NotMatched []string
}

func strList(rec gjson.Result, key string) []string {
	var out []string
	for _, v := range rec.Get(key).Array() {
		out = append(out, v.String())
	}
	return out
}

// enabledFlag parses ipaenabledflag, which arrives as ["TRUE"]/["FALSE"]
// strings on the wire (older servers) or as a plain bool (newer ones)
func enabledFlag(rec gjson.Result) bool {
	v := rec.Get("ipaenabledflag.0")
	if !v.Exists() {
		v = rec.Get("ipaenabledflag")
	}
	if v.Type == gjson.True || v.Type == gjson.False {
		return v.Bool()
	}
	return strings.EqualFold(v.String(), "TRUE")
}

func hbacRuleFromRecord(rec gjson.Result) *hbacRule {
	return &hbacRule{
		Name:             rec.Get("cn.0").String(),
		Description:      rec.Get("description.0").String(),
		Enabled:          enabledFlag(rec),
		UserCategory:     rec.Get("usercategory.0").String(),
		HostCategory:     rec.Get("hostcategory.0").String(),
		ServiceCategory:  rec.Get("servicecategory.0").String(),
		MemberUsers:      strList(rec, "memberuser_user"),
		MemberGroups:     strList(rec, "memberuser_group"),
		MemberHosts:      strList(rec, "memberhost_host"),
		MemberHostgroups: strList(rec, "memberhost_hostgroup"),
		MemberServices:   strList(rec, "memberservice_hbacsvc"),
	}
}

func sudoRuleFromRecord(rec gjson.Result) *sudoRule {
	return &sudoRule{
		Name:             rec.Get("cn.0").String(),
		Description:      rec.Get("description.0").String(),
		Enabled:          enabledFlag(rec),
		UserCategory:     rec.Get("usercategory.0").String(),
		HostCategory:     rec.Get("hostcategory.0").String(),
		CmdCategory:      rec.Get("cmdcategory.0").String(),
		MemberUsers:      strList(rec, "memberuser_user"),
		MemberGroups:     strList(rec, "memberuser_group"),
		MemberHosts:      strList(rec, "memberhost_host"),
		MemberHostgroups: strList(rec, "memberhost_hostgroup"),
		AllowCommands:    strList(rec, "memberallowcmd_sudocmd"),
		DenyCommands:     strList(rec, "memberdenycmd_sudocmd"),
		RunAsUsers:       strList(rec, "ipasudorunas_user"),
		RunAsGroups:      strList(rec, "ipasudorunasgroup_group"),
	}
}

func hbacRuleFind(client *ipa.Client) ([]*hbacRule, error) {
	res, err := ipaSessionRPC(client, "hbacrule_find", []string{}, map[string]interface{}{
		"all":       true,
		"sizelimit": 500,
	})
	if err != nil {
		return nil, err
	}
	rules := []*hbacRule{}
	for _, rec := range gjson.ParseBytes(res.Result.Data).Array() {
		rules = append(rules, hbacRuleFromRecord(rec))
	}
	return rules, nil
}

func sudoRuleFind(client *ipa.Client) ([]*sudoRule, error) {
	res, err := ipaSessionRPC(client, "sudorule_find", []string{}, map[string]interface{}{
		"all":       true,
		"sizelimit": 500,
	})
	if err != nil {
		return nil, err
	}
	rules := []*sudoRule{}
	for _, rec := range gjson.ParseBytes(res.Result.Data).Array() {
		rules = append(rules, sudoRuleFromRecord(rec))
	}
	return rules, nil
}

// hbacTest runs FreeIPA's server-side HBAC simulation over enabled rules
func hbacTest(client *ipa.Client, user, targethost, service string) (*hbacTestResult, error) {
	res, err := ipaSessionRPC(client, "hbactest", []string{}, map[string]interface{}{
		"user":       user,
		"targethost": targethost,
		"service":    service,
		"enabled":    true,
	})
	if err != nil {
		return nil, err
	}
	data := gjson.ParseBytes(res.Result.Data)
	out := &hbacTestResult{Granted: data.Get("value").Bool()}
	for _, v := range data.Get("matched").Array() {
		out.Matched = append(out.Matched, v.String())
	}
	for _, v := range data.Get("notmatched").Array() {
		out.NotMatched = append(out.NotMatched, v.String())
	}
	return out, nil
}

// ruleAppliesToUser: usercategory=all, direct uid membership, or a group
// intersection. Direct membership only — nested groups out of scope.
func ruleAppliesToUser(usercategory string, memberUsers, memberGroups []string, username string, userGroups []string) bool {
	if usercategory == "all" {
		return true
	}
	for _, u := range memberUsers {
		if u == username {
			return true
		}
	}
	for _, g := range memberGroups {
		for _, ug := range userGroups {
			if g == ug {
				return true
			}
		}
	}
	return false
}
