// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

type managedGroup struct {
	Group    *ipaGroup
	Requests []GroupRequest
}

// isManagerOf: username manages g directly or through a manager group
func isManagerOf(username string, userGroups []string, g *ipaGroup) bool {
	for _, m := range g.ManagerUsers {
		if m == username {
			return true
		}
	}
	for _, mg := range g.ManagerGroups {
		for _, ug := range userGroups {
			if mg == ug {
				return true
			}
		}
	}
	return false
}

// groupsVars fills the /groups template sections from one group_find
func (r *Router) groupsVars(c *fiber.Ctx, vars fiber.Map) {
	user := r.user(c)
	vars["my_groups"] = user.Groups

	groups, err := groupFindManaged(r.userClient(c))
	if err != nil {
		log.WithFields(log.Fields{
			"username": user.Username,
			"err":      err,
		}).Error("Failed to list managed groups")
		vars["groups_error"] = true
		return
	}

	joinable := []*ipaGroup{}
	myRequests := []string{}
	managed := []managedGroup{}

	for _, g := range groups {
		member := user.HasGroup(g.Name)

		if isManagerOf(user.Username, user.Groups, g) {
			// stale requests (requester became a member) are dropped
			reqs := []GroupRequest{}
			for _, req := range r.loadGroupRequests(g.Name) {
				queuedIsMember := false
				for _, m := range g.Members {
					if m == req.Username {
						queuedIsMember = true
						break
					}
				}
				if queuedIsMember {
					r.removeGroupRequest(g.Name, req.Username)
					continue
				}
				reqs = append(reqs, req)
			}
			managed = append(managed, managedGroup{Group: g, Requests: reqs})
		}

		if member {
			continue
		}

		pending := false
		for _, req := range r.loadGroupRequests(g.Name) {
			if req.Username == user.Username {
				pending = true
				break
			}
		}
		if pending {
			myRequests = append(myRequests, g.Name)
		} else {
			joinable = append(joinable, g)
		}
	}

	vars["joinable"] = joinable
	vars["my_requests"] = myRequests
	vars["managed"] = managed
}

// GroupRequestJoin queues a join request for a managed group and notifies
// its sponsors
func (r *Router) GroupRequestJoin(c *fiber.Ctx) error {
	user := r.user(c)
	groupName := c.FormValue("group")

	g, err := groupShow(r.userClient(c), groupName)
	if err != nil || !g.Managed() {
		return c.Status(fiber.StatusBadRequest).SendString(T("groups.not_joinable"))
	}
	if user.HasGroup(g.Name) {
		return c.Status(fiber.StatusBadRequest).SendString(T("groups.already_member"))
	}

	if r.addGroupRequest(g.Name, user.Username) {
		log.WithFields(log.Fields{
			"username": user.Username,
			"group":    g.Name,
			"ip":       RemoteIP(c),
		}).Info("AUDIT group join requested")

		go r.notifyGroupSponsors(g, user.Username)
	}

	vars := fiber.Map{"user": user}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// notifyGroupSponsors emails every direct member manager of the group.
// Runs in a goroutine after the handler returns, so it must not touch the
// fiber ctx (fiber recycles it) — SendGroupRequestEmail takes no ctx,
// mirroring SendNewLoginEmail.
// ponytail: manager groups are not expanded to individual recipients —
// direct managers only; expand if a deployment actually runs on
// manager-groups alone.
func (r *Router) notifyGroupSponsors(g *ipaGroup, requester string) {
	for _, m := range g.ManagerUsers {
		manager, err := r.adminClient.UserShow(m)
		if err != nil {
			log.WithFields(log.Fields{"manager": m, "err": err}).Error("Failed to fetch group manager for notification")
			continue
		}
		if err := r.emailer.SendGroupRequestEmail(manager, requester, g.Name); err != nil {
			log.WithFields(log.Fields{"manager": m, "err": err}).Error("Failed to send group request email")
		}
	}
}
