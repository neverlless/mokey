// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	ipa "github.com/neverlless/goipa"
)

// hbacrule_find / sudorule_find / hbactest are readable/runnable by any authenticated user — "System: Read
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

func hbacRuleFrom(r *ipa.HBACRule) *hbacRule {
	return &hbacRule{
		Name:             r.Name,
		Description:      r.Description,
		Enabled:          r.Enabled,
		UserCategory:     r.UserCategory,
		HostCategory:     r.HostCategory,
		ServiceCategory:  r.ServiceCategory,
		MemberUsers:      r.Users,
		MemberGroups:     r.Groups,
		MemberHosts:      r.Hosts,
		MemberHostgroups: r.HostGroups,
		MemberServices:   r.Services,
	}
}

func sudoRuleFrom(r *ipa.SudoRule) *sudoRule {
	return &sudoRule{
		Name:             r.Name,
		Description:      r.Description,
		Enabled:          r.Enabled,
		UserCategory:     r.UserCategory,
		HostCategory:     r.HostCategory,
		CmdCategory:      r.CmdCategory,
		MemberUsers:      r.Users,
		MemberGroups:     r.Groups,
		MemberHosts:      r.Hosts,
		MemberHostgroups: r.HostGroups,
		AllowCommands:    r.AllowCommands,
		DenyCommands:     r.DenyCommands,
		RunAsUsers:       r.RunAsUsers,
		RunAsGroups:      r.RunAsGroups,
	}
}

// ruleSizeLimit caps hbacrule_find/sudorule_find result sets. goipa's
// HBACRuleFind/SudoRuleFind don't report FreeIPA's truncated flag, so
// truncation is detected below by a count heuristic instead.
const ruleSizeLimit = 500

func hbacRuleFind(client *ipa.Client) ([]*hbacRule, bool, error) {
	found, err := client.HBACRuleFind(ipa.Options{"sizelimit": ruleSizeLimit})
	if err != nil {
		return nil, false, err
	}
	rules := []*hbacRule{}
	for _, r := range found {
		rules = append(rules, hbacRuleFrom(r))
	}
	// ponytail: count heuristic, not the real truncated flag — exact-limit
	// hits are assumed truncated. Upgrade to FindEntries + ErrTruncated if
	// the false positive ever matters.
	return rules, len(rules) >= ruleSizeLimit, nil
}

func sudoRuleFind(client *ipa.Client) ([]*sudoRule, bool, error) {
	found, err := client.SudoRuleFind(ipa.Options{"sizelimit": ruleSizeLimit})
	if err != nil {
		return nil, false, err
	}
	rules := []*sudoRule{}
	for _, r := range found {
		rules = append(rules, sudoRuleFrom(r))
	}
	return rules, len(rules) >= ruleSizeLimit, nil
}

// hbacTest runs FreeIPA's server-side HBAC simulation over enabled rules
func hbacTest(client *ipa.Client, user, targethost, service string) (*hbacTestResult, error) {
	res, err := client.HBACTest(user, targethost, service)
	if err != nil {
		return nil, err
	}
	return &hbacTestResult{
		Granted:    res.Granted,
		Matched:    res.Matched,
		NotMatched: res.NotMatched,
	}, nil
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
