package server

import (
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

// MaxGroups caps the groups one invite may carry.
const MaxGroups = 20

// InviteGroup is a group an invited account joins on acceptance; Duration
// is empty for no end date.
type InviteGroup struct {
	Name     string `json:"name"`
	Duration string `json:"duration,omitempty"`
}

type inviteGroupChoice struct {
	Name, Description string
	Durations         []durationOption
}

func (r *Router) inviteGroupsOn() bool {
	return viper.GetBool("admin.invite_groups")
}

// inviteGroupChoices lists the groups the current user may put an invitee
// in: managed by them and not owned by sync.
func (r *Router) inviteGroupChoices(c fiber.Ctx) ([]inviteGroupChoice, error) {
	user := r.user(c)
	groups, err := groupFindManaged(r.userClient(c))
	if err != nil {
		return nil, err
	}
	lang := requestLanguage(c)
	choices := []inviteGroupChoice{}
	for _, g := range groups {
		if !isManagerOf(user.Username, user.Groups, g) || r.syncMapped(g.Name) {
			continue
		}
		choice := inviteGroupChoice{Name: g.Name, Description: g.Description}
		if r.groupExpiry.Enabled() {
			choice.Durations = r.durationOptions(lang, g.Name)
		}
		choices = append(choices, choice)
	}
	slices.SortFunc(choices, func(a, b inviteGroupChoice) int { return strings.Compare(a.Name, b.Name) })
	return choices, nil
}

// inviteGroupsFromForm reads the ticked groups and their durations; the
// error carries the form message to show.
func (r *Router) inviteGroupsFromForm(c fiber.Ctx) ([]InviteGroup, error) {
	names := []string{}
	for _, v := range c.Request().PostArgs().PeekMulti("groups") {
		if name := strings.TrimSpace(string(v)); name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	if !r.inviteGroupsOn() {
		return nil, errors.New(TC(c, "admin.invite_groups_off"))
	}
	if len(names) > MaxGroups {
		return nil, errors.New(TC(c, "admin.invite_groups_too_many"))
	}

	choices, err := r.inviteGroupChoices(c)
	if err != nil {
		slog.Error("Failed to list groups for an invite",
			"username", r.username(c),
			"err", err,
		)
		return nil, errors.New(TC(c, "account.fatal_system_error"))
	}
	groups := []InviteGroup{}
	for _, name := range names {
		if !slices.ContainsFunc(choices, func(ch inviteGroupChoice) bool { return ch.Name == name }) {
			return nil, errors.New(TC(c, "admin.invite_group_not_allowed"))
		}
		duration := strings.TrimSpace(c.FormValue("duration_" + name))
		if _, ok := r.groupDuration(name, duration); !ok {
			return nil, errors.New(TC(c, "admin.invite_group_duration"))
		}
		groups = append(groups, InviteGroup{Name: name, Duration: duration})
	}
	return groups, nil
}

// applyInviteGroups adds a just-created invited account to the groups in
// its invite. Rights are checked again: they may have changed since the
// invite was sent. Failures are audited, never returned.
func (r *Router) applyInviteGroups(username string, invite *Token) {
	if len(invite.Groups) == 0 {
		return
	}
	skip := func(group, reason string, err error) {
		attrs := []any{"group", group, "username", username, "invited_by", invite.InvitedBy, "reason", reason}
		if err != nil {
			attrs = append(attrs, "err", err)
		}
		slog.Warn("AUDIT invite group skipped", attrs...)
	}
	if !r.inviteGroupsOn() {
		for _, g := range invite.Groups {
			skip(g.Name, "disabled", nil)
		}
		return
	}

	inviter, err := r.adminClient.UserShow(invite.InvitedBy)
	if err != nil {
		for _, g := range invite.Groups {
			skip(g.Name, "failed", err)
		}
		return
	}

	for _, ig := range invite.Groups {
		if r.syncMapped(ig.Name) {
			skip(ig.Name, "sync", nil)
			continue
		}
		g, err := groupShow(r.adminClient, ig.Name)
		switch {
		case err != nil:
			skip(ig.Name, "failed", err)
			continue
		case !g.Managed():
			skip(ig.Name, "not managed", nil)
			continue
		case !isManagerOf(inviter.Username, inviter.Groups, g):
			skip(ig.Name, "not a manager", nil)
			continue
		}
		d, ok := r.groupDuration(ig.Name, ig.Duration)
		if !ok {
			skip(ig.Name, "invalid duration", nil)
			continue
		}

		// the invitee has no session yet and the inviter isn't here: mokey's
		// service account adds, after the inviter's rights were checked above
		if err := groupAddMember(r.adminClient, ig.Name, username); err != nil {
			skip(ig.Name, "failed", err)
			continue
		}
		var until time.Time
		if d > 0 {
			until = time.Now().Add(d)
		}
		if err := r.recordGrantAs(r.adminClient, invite.InvitedBy, ig.Name, username, until); err != nil {
			if !errors.Is(err, errGrantedWithoutEnd) {
				skip(ig.Name, "failed", err)
			}
			continue
		}

		attrs := []any{"group", ig.Name, "username", username, "invited_by", invite.InvitedBy}
		if !until.IsZero() {
			attrs = append(attrs, "until", until)
		}
		slog.Info("AUDIT invited user added to group", attrs...)
	}
}
