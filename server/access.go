// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// accessVars fills the Access tab: HBAC and sudo rules that apply to the
// logged-in user. Both reads run under the user's own session — default
// FreeIPA permissions make the rule sets world-readable to authenticated
// users, so no admin client and no extra privileges are involved.
func (r *Router) accessVars(c fiber.Ctx, vars fiber.Map) {
	user := r.user(c)
	client := r.userClient(c)

	hbac, hbacTruncated, err := hbacRuleFind(client)
	if err != nil {
		slog.Error("Failed to list HBAC rules",
			"username", user.Username,
			"err", err,
		)
		vars["access_error"] = true
		return
	}
	sudo, sudoTruncated, err := sudoRuleFind(client)
	if err != nil {
		slog.Error("Failed to list sudo rules",
			"username", user.Username,
			"err", err,
		)
		vars["access_error"] = true
		return
	}
	if hbacTruncated || sudoTruncated {
		vars["access_truncated"] = true
	}

	myHBAC := []*hbacRule{}
	for _, rule := range hbac {
		if rule.Enabled && ruleAppliesToUser(rule.UserCategory, rule.MemberUsers, rule.MemberGroups, user.Username, memberOf(user)) {
			myHBAC = append(myHBAC, rule)
		}
	}
	mySudo := []*sudoRule{}
	for _, rule := range sudo {
		if rule.Enabled && ruleAppliesToUser(rule.UserCategory, rule.MemberUsers, rule.MemberGroups, user.Username, memberOf(user)) {
			mySudo = append(mySudo, rule)
		}
	}

	vars["hbac_rules"] = myHBAC
	vars["sudo_rules"] = mySudo
}

// AccessTest runs FreeIPA's hbactest for the SESSION user against a
// host/service from the form. The username never comes from the form —
// users can only simulate their own access.
func (r *Router) AccessTest(c fiber.Ctx) error {
	username := r.username(c)

	host := strings.TrimSpace(c.FormValue("host"))
	service := strings.TrimSpace(c.FormValue("service"))
	if service == "" {
		service = "sshd"
	}
	if host == "" || len(host) > 255 || len(service) > 255 {
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, "access.host_required"))
	}

	res, err := hbacTest(r.userClient(c), username, host, service)
	if err != nil {
		slog.Error("hbactest failed",
			"username", username,
			"host", host,
			"err", err,
		)
		return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "account.fatal_system_error"))
	}

	slog.Debug("hbactest simulated",
		"username", username,
		"host", host,
		"service", service,
		"granted", res.Granted,
	)

	return c.Render("access-test-result.html", fiber.Map{
		"granted": res.Granted,
		"matched": res.Matched,
		"host":    host,
		"service": service,
	})
}
