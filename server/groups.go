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
