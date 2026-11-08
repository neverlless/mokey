// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"log/slog"
	"slices"
	"time"

	"github.com/gofiber/fiber/v3"
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
func (r *Router) groupsVars(c fiber.Ctx, vars fiber.Map) {
	user := r.user(c)
	vars["my_groups"] = user.Groups

	groups, err := groupFindManaged(r.userClient(c))
	if err != nil {
		slog.Error("Failed to list managed groups",
			"username", user.Username,
			"err", err,
		)
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
func (r *Router) GroupRequestJoin(c fiber.Ctx) error {
	if ferr := r.requestJoin(c, c.FormValue("group"), c.FormValue("duration")); ferr != nil {
		return c.Status(ferr.Code).SendString(ferr.Message)
	}

	vars := fiber.Map{"user": r.user(c)}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// requestJoin queues the caller's join request and notifies the sponsors;
// shared by the Groups and Apps pages
func (r *Router) requestJoin(c fiber.Ctx, groupName, duration string) *fiber.Error {
	user := r.user(c)

	g, err := groupShow(r.userClient(c), groupName)
	if err != nil || !g.Managed() {
		return fiber.NewError(fiber.StatusBadRequest, TC(c, "groups.not_joinable"))
	}
	if user.HasGroup(g.Name) {
		return fiber.NewError(fiber.StatusBadRequest, TC(c, "groups.already_member"))
	}
	if _, ok := r.groupDuration(g.Name, duration); !ok {
		return fiber.NewError(fiber.StatusBadRequest, TC(c, "groups.invalid_duration"))
	}

	if r.addGroupRequest(g.Name, user.Username, groupRequestJoin, duration) {
		slog.Info("AUDIT group join requested",
			"username", user.Username,
			"group", g.Name,
			"duration", duration,
			"ip", RemoteIP(c),
		)

		r.goBG(func() { r.notifyGroupSponsors(g, user.Username, groupRequestJoin, duration) })
	}
	return nil
}

// GroupRequestLeave queues a leave request for a group the user belongs to
// and notifies its sponsors. Membership can only be mutated by a sponsor's
// session (see groupAddMember), so leaving goes through the same approval
// queue as joining rather than executing instantly.
func (r *Router) GroupRequestLeave(c fiber.Ctx) error {
	user := r.user(c)
	groupName := c.FormValue("group")

	g, err := groupShow(r.userClient(c), groupName)
	if err != nil || !g.Managed() {
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, "groups.not_joinable"))
	}
	if !user.HasGroup(g.Name) {
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, "groups.not_a_member"))
	}

	if r.addGroupRequest(g.Name, user.Username, groupRequestLeave, "") {
		slog.Info("AUDIT group leave requested",
			"username", user.Username,
			"group", g.Name,
			"ip", RemoteIP(c),
		)

		r.goBG(func() { r.notifyGroupSponsors(g, user.Username, groupRequestLeave, "") })
	}

	vars := fiber.Map{"user": user}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// groupDecision validates that the caller sponsors the group and the
// target is queued; shared by approve and deny
func (r *Router) groupDecision(c fiber.Ctx) (*ipaGroup, GroupRequest, error) {
	user := r.user(c)
	groupName := c.FormValue("group")
	target := c.FormValue("username")

	g, err := groupShow(r.userClient(c), groupName)
	if err != nil {
		return nil, GroupRequest{}, fiber.NewError(fiber.StatusBadRequest, TC(c, "groups.not_joinable"))
	}
	if !isManagerOf(user.Username, user.Groups, g) {
		return nil, GroupRequest{}, fiber.NewError(fiber.StatusForbidden, TC(c, "groups.not_a_manager"))
	}
	for _, req := range r.loadGroupRequests(g.Name) {
		if req.Username == target {
			return g, req, nil
		}
	}
	return nil, GroupRequest{}, fiber.NewError(fiber.StatusBadRequest, TC(c, "groups.no_such_request"))
}

// groupDuration parses a posted duration and checks it is offered for
// group; "" is permanent
func (r *Router) groupDuration(group, s string) (time.Duration, bool) {
	if s == "" {
		return 0, r.groupExpiry.Allowed(group, 0)
	}
	d, err := parseGroupDuration(s)
	return d, err == nil && r.groupExpiry.Allowed(group, d)
}

// approvedDuration is the sponsor's pick for a join request: offered for
// the group and never longer than requested
func (r *Router) approvedDuration(c fiber.Ctx, group string, req GroupRequest) (time.Duration, bool) {
	posted := c.FormValue("duration")
	if !c.Request().PostArgs().Has("duration") {
		posted = ""
		if r.groupExpiry.Enabled() {
			posted = req.Duration
		}
	}
	d, ok := r.groupDuration(group, posted)
	if !ok || !r.groupExpiry.Enabled() || req.Duration == "" {
		return d, ok
	}
	requested, err := parseGroupDuration(req.Duration)
	return d, err == nil && d != 0 && d <= requested
}

func (r *Router) GroupApprove(c fiber.Ctx) error {
	g, req, err := r.groupDecision(c)
	if err != nil {
		ferr := err.(*fiber.Error)
		return c.Status(ferr.Code).SendString(ferr.Message)
	}

	vars := fiber.Map{}
	var until time.Time
	// the sponsor's own session performs the change; FreeIPA enforces
	// member-manager rights even if mokey's check were bypassed
	mutate := groupAddMember
	action := "AUDIT group join approved"
	if req.Type == groupRequestLeave {
		mutate = groupRemoveMember
		action = "AUDIT group leave approved"
	} else {
		d, ok := r.approvedDuration(c, g.Name, req)
		if !ok {
			return c.Status(fiber.StatusBadRequest).SendString(TC(c, "groups.invalid_duration"))
		}
		// mokey never records an end date for a membership it did not add
		if slices.Contains(g.Members, req.Username) {
			mutate = nil
			vars["groups_notice"] = TC(c, "groups.already_member_no_end")
		} else if d > 0 {
			until = time.Now().Add(d)
		}
	}
	if mutate != nil {
		if err := mutate(r.userClient(c), g.Name, req.Username); err != nil {
			slog.Error("Group approve failed in FreeIPA",
				"group", g.Name,
				"username", req.Username,
				"sponsor", r.username(c),
				"err", err,
			)
			return c.Status(fiber.StatusForbidden).SendString(TC(c, "groups.approve_failed"))
		}
		if req.Type == groupRequestJoin {
			if err := r.recordGrant(c, g.Name, req.Username, until); err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "groups.expiry_store_failed"))
			}
		}
	}

	r.removeGroupRequest(g.Name, req.Username)
	attrs := []any{
		"group", g.Name,
		"username", req.Username,
		"sponsor", r.username(c),
		"ip", RemoteIP(c),
	}
	if !until.IsZero() {
		attrs = append(attrs, "until", until)
	}
	slog.Info(action, attrs...)

	r.sendGroupDecision(req.Username, g.Name, true, req.Type, until)
	if req.Type == groupRequestLeave {
		r.goBG(func() { r.revokeConsentsOf(req.Username) })
	}

	vars["user"] = r.user(c)
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// recordGrant stores the end date of a membership just added (zero until:
// permanent, dropping any earlier record). On failure the membership is
// removed again: a time-bound grant must never stay without its record.
func (r *Router) recordGrant(c fiber.Ctx, group, username string, until time.Time) error {
	var err error
	if until.IsZero() {
		var m *TimedMembership
		if m, err = r.timedMember(group, username); err != nil || m != nil {
			err = r.dropTimedMember(group, username)
		}
	} else {
		err = r.putTimedMember(TimedMembership{
			Group:     group,
			Username:  username,
			Until:     until,
			GrantedBy: r.username(c),
			GrantedAt: time.Now(),
		})
	}
	if err == nil {
		return nil
	}
	slog.Error("Failed to store membership end date, rolling back the grant",
		"group", group,
		"username", username,
		"err", err,
	)
	if rerr := groupRemoveMember(r.userClient(c), group, username); rerr != nil {
		slog.Error("Rollback failed: membership left without its end date record",
			"group", group,
			"username", username,
			"sponsor", r.username(c),
			"err", rerr,
		)
	}
	return err
}

func (r *Router) GroupDeny(c fiber.Ctx) error {
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
	slog.Info(action,
		"group", g.Name,
		"username", req.Username,
		"sponsor", r.username(c),
		"ip", RemoteIP(c),
	)

	r.sendGroupDecision(req.Username, g.Name, false, req.Type, time.Time{})

	vars := fiber.Map{"user": r.user(c)}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// GroupRemoveMember lets a sponsor remove a member directly, independent of
// the leave-request queue — the sponsor already holds standing authority
// over the group, the same authority Approve exercises.
func (r *Router) GroupRemoveMember(c fiber.Ctx) error {
	user := r.user(c)
	groupName := c.FormValue("group")
	target := c.FormValue("username")

	g, err := groupShow(r.userClient(c), groupName)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, "groups.not_joinable"))
	}
	if !isManagerOf(user.Username, user.Groups, g) {
		return c.Status(fiber.StatusForbidden).SendString(TC(c, "groups.not_a_manager"))
	}

	if err := groupRemoveMember(r.userClient(c), g.Name, target); err != nil {
		slog.Error("Group member removal failed in FreeIPA",
			"group", g.Name,
			"username", target,
			"sponsor", user.Username,
			"err", err,
		)
		return c.Status(fiber.StatusForbidden).SendString(TC(c, "groups.remove_failed"))
	}

	r.removeGroupRequest(g.Name, target)
	slog.Info("AUDIT group member removed",
		"group", g.Name,
		"username", target,
		"sponsor", user.Username,
		"ip", RemoteIP(c),
	)

	r.goBG(func() { r.notifyGroupRemoved(target, g.Name) })
	r.goBG(func() { r.revokeConsentsOf(target) })

	vars := fiber.Map{"user": user}
	r.groupsVars(c, vars)
	return c.Render("groups-list.html", vars)
}

// sendGroupDecision emails the requester about the outcome (fire and log)
func (r *Router) sendGroupDecision(username, group string, approved bool, reqType string, until time.Time) {
	target, err := r.adminClient.UserShow(username)
	if err != nil {
		slog.Error("Failed to fetch requester for decision email", "username", username, "err", err)
		return
	}
	if err := r.emailer.SendGroupDecisionEmail(target, group, approved, reqType, until); err != nil {
		slog.Error("Failed to send group decision email", "username", username, "err", err)
	}
}

// notifyGroupRemoved emails a member removed directly by a sponsor. Runs in
// a goroutine after the handler returns, mirrors sendGroupDecision's nil-ctx
// mechanism.
func (r *Router) notifyGroupRemoved(username, group string) {
	target, err := r.adminClient.UserShow(username)
	if err != nil {
		slog.Error("Failed to fetch removed member for notification", "username", username, "err", err)
		return
	}
	if err := r.emailer.SendGroupRemovedEmail(target, group); err != nil {
		slog.Error("Failed to send group removed email", "username", username, "err", err)
	}
}

// notifyGroupSponsors emails every direct member manager of the group.
// Runs in a goroutine after the handler returns, so it must not touch the
// fiber ctx (fiber recycles it) — SendGroupRequestEmail takes no ctx,
// mirroring SendNewLoginEmail.
// ponytail: manager groups are not expanded to individual recipients —
// direct managers only; expand if a deployment actually runs on
// manager-groups alone.
func (r *Router) notifyGroupSponsors(g *ipaGroup, requester, reqType, duration string) {
	for _, m := range g.ManagerUsers {
		manager, err := r.adminClient.UserShow(m)
		if err != nil {
			slog.Error("Failed to fetch group manager for notification", "manager", m, "err", err)
			continue
		}
		if err := r.emailer.SendGroupRequestEmail(manager, requester, g.Name, reqType, duration); err != nil {
			slog.Error("Failed to send group request email", "manager", m, "err", err)
		}
	}
}
