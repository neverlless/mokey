//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The groups on an invite are added by mokey's service account when the
// invitee accepts, which needs the membership permission of the time-bound
// groups; the inviter's manager rights are checked again at that moment.
func TestInviteGroupsOnRealFreeIPA(t *testing.T) {
	stand(t)
	grantMembershipWrite(t)

	inviter, other := newUser(t), newUser(t)
	mustIPA(t, "group-add-member", "admins", "--users="+inviter.uid)
	managed, foreign := "inv"+runID, "invnm"+runID
	for g, manager := range map[string]string{managed: inviter.uid, foreign: other.uid} {
		mustIPA(t, "group-add", g, "--desc=mokey integration")
		t.Cleanup(func() { _, _ = ipaCmd("", "group-del", g) })
		mustIPA(t, "group-add-member-manager", g, "--users="+manager)
	}
	admin := login(t, inviter.uid, inviter.password)

	invite := func(group string) (uid, email string, body string) {
		t.Helper()
		uid = "it" + randHex(4)
		email = uid + "@example.org"
		code, body := admin.hx("/admin/invite", url.Values{"email": {email}, "username": {uid}, "groups": {group}})
		if code != http.StatusOK {
			t.Fatalf("invite %s: %d: %s", group, code, body)
		}
		return uid, email, body
	}
	accept := func(uid, email string) {
		t.Helper()
		cleanupUser(t, uid)
		link := mailLink(t, email, "/auth/invite/")
		c := newClient(t)
		c.get(link)
		pw := newPassword()
		if code, body := c.post(link, url.Values{"first": {"It"}, "last": {"Invite"}, "password": {pw}, "password2": {pw}}); code != http.StatusOK {
			t.Fatalf("accept invite: %d: %s", code, body)
		}
		mustIPA(t, "user-show", uid)
	}

	_, email, body := invite(foreign)
	if !strings.Contains(body, "You can only add the invitee to groups you manage") || strings.Contains(body, "Invitation sent to") {
		t.Fatalf("invite to a group the admin doesn't manage was not refused: %s", body)
	}
	var found struct{ Messages []struct{ ID string } }
	getJSON(t, mailpitURL+"/api/v1/search?"+url.Values{"query": {`to:"` + email + `"`}}.Encode(), &found)
	if len(found.Messages) != 0 {
		t.Fatalf("refused invite sent %d mails to %s", len(found.Messages), email)
	}

	uid, email, body := invite(managed)
	if !strings.Contains(body, "Invitation sent to") {
		t.Fatalf("invite to %s: %s", managed, body)
	}
	accept(uid, email)
	if !strings.Contains(mustIPA(t, "group-show", managed), uid) {
		t.Fatalf("invited %s is not a member of %s", uid, managed)
	}

	// Another manager keeps the group in the permission's filter, so only
	// mokey's own check can keep the invitee out
	uid, email, _ = invite(managed)
	mustIPA(t, "group-add-member-manager", managed, "--users="+other.uid)
	mustIPA(t, "group-remove-member-manager", managed, "--users="+inviter.uid)
	accept(uid, email)
	if strings.Contains(mustIPA(t, "group-show", managed), uid) {
		t.Fatalf("%s joined %s although the inviter no longer manages it", uid, managed)
	}
	logs, _ := runDocker("", "logs", mokeyCtr)
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "AUDIT invite group skipped") && strings.Contains(line, uid) && strings.Contains(line, "not a manager") {
			return
		}
	}
	t.Errorf("no \"not a manager\" skip audit event for %s in the mokey log", uid)
}
