// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

// accessVars fills the Access tab: HBAC and sudo rules that apply to the
// logged-in user. Both reads run under the user's own session — default
// FreeIPA permissions make the rule sets world-readable to authenticated
// users, so no admin client and no extra privileges are involved.
func (r *Router) accessVars(c *fiber.Ctx, vars fiber.Map) {
	user := r.user(c)
	client := r.userClient(c)

	hbac, err := hbacRuleFind(client)
	if err != nil {
		log.WithFields(log.Fields{
			"username": user.Username,
			"err":      err,
		}).Error("Failed to list HBAC rules")
		vars["access_error"] = true
		return
	}
	sudo, err := sudoRuleFind(client)
	if err != nil {
		log.WithFields(log.Fields{
			"username": user.Username,
			"err":      err,
		}).Error("Failed to list sudo rules")
		vars["access_error"] = true
		return
	}

	myHBAC := []*hbacRule{}
	for _, rule := range hbac {
		if rule.Enabled && ruleAppliesToUser(rule.UserCategory, rule.MemberUsers, rule.MemberGroups, user.Username, user.Groups) {
			myHBAC = append(myHBAC, rule)
		}
	}
	mySudo := []*sudoRule{}
	for _, rule := range sudo {
		if rule.Enabled && ruleAppliesToUser(rule.UserCategory, rule.MemberUsers, rule.MemberGroups, user.Username, user.Groups) {
			mySudo = append(mySudo, rule)
		}
	}

	vars["hbac_rules"] = myHBAC
	vars["sudo_rules"] = mySudo
}
