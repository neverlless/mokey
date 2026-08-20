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

// myGroupRequest is a pending join or leave request shown to its requester
type myGroupRequest struct {
	Group string
	Type  string
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
	leavable := []*ipaGroup{}
	myRequests := []myGroupRequest{}
	managed := []managedGroup{}

	for _, g := range groups {
		member := user.HasGroup(g.Name)

		// stale requests are dropped: a join request where the requester is
		// already a member, or a leave request where they no longer are
		reqs := []GroupRequest{}
		var myPending string
		for _, req := range r.loadGroupRequests(g.Name) {
			queuedIsMember := false
			for _, m := range g.Members {
				if m == req.Username {
					queuedIsMember = true
					break
				}
			}
			// join requests go stale once fulfilled (already a member);
			// leave requests go stale once fulfilled (no longer a member)
			stale := queuedIsMember
			if req.Type == groupRequestLeave {
				stale = !queuedIsMember
			}
			if stale {
				r.removeGroupRequest(g.Name, req.Username)
				continue
			}
			reqs = append(reqs, req)
			if req.Username == user.Username {
				myPending = req.Type
			}
		}

		if isManagerOf(user.Username, user.Groups, g) {
			managed = append(managed, managedGroup{Group: g, Requests: reqs})
		}

		if member {
			if myPending == groupRequestLeave {
				myRequests = append(myRequests, myGroupRequest{Group: g.Name, Type: groupRequestLeave})
			} else {
				leavable = append(leavable, g)
			}
			continue
		}

		if myPending == groupRequestJoin {
			myRequests = append(myRequests, myGroupRequest{Group: g.Name, Type: groupRequestJoin})
		} else {
			joinable = append(joinable, g)
		}
	}

	vars["joinable"] = joinable
	vars["leavable"] = leavable
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

	if r.addGroupRequest(g.Name, user.Username, groupRequestJoin) {
		log.WithFields(log.Fields{
			"username": user.Username,
			"group":    g.Name,
			"ip":       RemoteIP(c),
		}).Info("AUDIT group join requested")

		go r.notifyGroupSponsors(g, user.Username, groupRequestJoin)
	}

	vars := fiber.Map{"user": user}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// GroupRequestLeave queues a leave request for a group the user belongs to
// and notifies its sponsors. Membership can only be mutated by a sponsor's
// session (see groupAddMember), so leaving goes through the same approval
// queue as joining rather than executing instantly.
func (r *Router) GroupRequestLeave(c *fiber.Ctx) error {
	user := r.user(c)
	groupName := c.FormValue("group")

	g, err := groupShow(r.userClient(c), groupName)
	if err != nil || !g.Managed() {
		return c.Status(fiber.StatusBadRequest).SendString(T("groups.not_joinable"))
	}
	if !user.HasGroup(g.Name) {
		return c.Status(fiber.StatusBadRequest).SendString(T("groups.not_a_member"))
	}

	if r.addGroupRequest(g.Name, user.Username, groupRequestLeave) {
		log.WithFields(log.Fields{
			"username": user.Username,
			"group":    g.Name,
			"ip":       RemoteIP(c),
		}).Info("AUDIT group leave requested")

		go r.notifyGroupSponsors(g, user.Username, groupRequestLeave)
	}

	vars := fiber.Map{"user": user}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// groupDecision validates that the caller sponsors the group and the
// target is queued; shared by approve and deny
func (r *Router) groupDecision(c *fiber.Ctx) (*ipaGroup, GroupRequest, error) {
	user := r.user(c)
	groupName := c.FormValue("group")
	target := c.FormValue("username")

	g, err := groupShow(r.userClient(c), groupName)
	if err != nil {
		return nil, GroupRequest{}, fiber.NewError(fiber.StatusBadRequest, T("groups.not_joinable"))
	}
	if !isManagerOf(user.Username, user.Groups, g) {
		return nil, GroupRequest{}, fiber.NewError(fiber.StatusForbidden, T("groups.not_a_manager"))
	}
	for _, req := range r.loadGroupRequests(g.Name) {
		if req.Username == target {
			return g, req, nil
		}
	}
	return nil, GroupRequest{}, fiber.NewError(fiber.StatusBadRequest, T("groups.no_such_request"))
}

func (r *Router) GroupApprove(c *fiber.Ctx) error {
	g, req, err := r.groupDecision(c)
	if err != nil {
		ferr := err.(*fiber.Error)
		return c.Status(ferr.Code).SendString(ferr.Message)
	}

	// the sponsor's own session performs the change; FreeIPA enforces
	// member-manager rights even if mokey's check were bypassed
	mutate := groupAddMember
	action := "AUDIT group join approved"
	if req.Type == groupRequestLeave {
		mutate = groupRemoveMember
		action = "AUDIT group leave approved"
	}
	if err := mutate(r.userClient(c), g.Name, req.Username); err != nil {
		log.WithFields(log.Fields{
			"group":    g.Name,
			"username": req.Username,
			"sponsor":  r.username(c),
			"err":      err,
		}).Error("Group approve failed in FreeIPA")
		return c.Status(fiber.StatusForbidden).SendString(T("groups.approve_failed"))
	}

	r.removeGroupRequest(g.Name, req.Username)
	log.WithFields(log.Fields{
		"group":    g.Name,
		"username": req.Username,
		"sponsor":  r.username(c),
		"ip":       RemoteIP(c),
	}).Info(action)

	r.sendGroupDecision(req.Username, g.Name, true, req.Type)

	vars := fiber.Map{"user": r.user(c)}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

func (r *Router) GroupDeny(c *fiber.Ctx) error {
	g, req, err := r.groupDecision(c)
	if err != nil {
		ferr := err.(*fiber.Error)
		return c.Status(ferr.Code).SendString(ferr.Message)
	}

	r.removeGroupRequest(g.Name, req.Username)
	action := "AUDIT group join denied"
	if req.Type == groupRequestLeave {
		action = "AUDIT group leave denied"
	}
	log.WithFields(log.Fields{
		"group":    g.Name,
		"username": req.Username,
		"sponsor":  r.username(c),
		"ip":       RemoteIP(c),
	}).Info(action)

	r.sendGroupDecision(req.Username, g.Name, false, req.Type)

	vars := fiber.Map{"user": r.user(c)}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// GroupRemoveMember lets a sponsor remove a member directly, independent of
// the leave-request queue — the sponsor already holds standing authority
// over the group, the same authority Approve exercises.
func (r *Router) GroupRemoveMember(c *fiber.Ctx) error {
	user := r.user(c)
	groupName := c.FormValue("group")
	target := c.FormValue("username")

	g, err := groupShow(r.userClient(c), groupName)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(T("groups.not_joinable"))
	}
	if !isManagerOf(user.Username, user.Groups, g) {
		return c.Status(fiber.StatusForbidden).SendString(T("groups.not_a_manager"))
	}

	if err := groupRemoveMember(r.userClient(c), g.Name, target); err != nil {
		log.WithFields(log.Fields{
			"group":    g.Name,
			"username": target,
			"sponsor":  user.Username,
			"err":      err,
		}).Error("Group member removal failed in FreeIPA")
		return c.Status(fiber.StatusForbidden).SendString(T("groups.remove_failed"))
	}

	r.removeGroupRequest(g.Name, target)
	log.WithFields(log.Fields{
		"group":    g.Name,
		"username": target,
		"sponsor":  user.Username,
		"ip":       RemoteIP(c),
	}).Info("AUDIT group member removed")

	go r.notifyGroupRemoved(target, g.Name)

	vars := fiber.Map{"user": user}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// sendGroupDecision emails the requester about the outcome (fire and log)
func (r *Router) sendGroupDecision(username, group string, approved bool, reqType string) {
	target, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{"username": username, "err": err}).Error("Failed to fetch requester for decision email")
		return
	}
	if err := r.emailer.SendGroupDecisionEmail(target, group, approved, reqType); err != nil {
		log.WithFields(log.Fields{"username": username, "err": err}).Error("Failed to send group decision email")
	}
}

// notifyGroupRemoved emails a member removed directly by a sponsor. Runs in
// a goroutine after the handler returns, mirrors sendGroupDecision's nil-ctx
// mechanism.
func (r *Router) notifyGroupRemoved(username, group string) {
	target, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{"username": username, "err": err}).Error("Failed to fetch removed member for notification")
		return
	}
	if err := r.emailer.SendGroupRemovedEmail(target, group); err != nil {
		log.WithFields(log.Fields{"username": username, "err": err}).Error("Failed to send group removed email")
	}
}

// notifyGroupSponsors emails every direct member manager of the group.
// Runs in a goroutine after the handler returns, so it must not touch the
// fiber ctx (fiber recycles it) — SendGroupRequestEmail takes no ctx,
// mirroring SendNewLoginEmail.
// ponytail: manager groups are not expanded to individual recipients —
// direct managers only; expand if a deployment actually runs on
// manager-groups alone.
func (r *Router) notifyGroupSponsors(g *ipaGroup, requester, reqType string) {
	for _, m := range g.ManagerUsers {
		manager, err := r.adminClient.UserShow(m)
		if err != nil {
			log.WithFields(log.Fields{"manager": m, "err": err}).Error("Failed to fetch group manager for notification")
			continue
		}
		if err := r.emailer.SendGroupRequestEmail(manager, requester, g.Name, reqType); err != nil {
			log.WithFields(log.Fields{"manager": m, "err": err}).Error("Failed to send group request email")
		}
	}
}
