package server

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestInviteAcceptFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)

	// token as InviteSend would issue it (email is both username and email)
	token, err := NewToken("kim@example.com", "kim@example.com", TokenInvite, router.storage)
	assert.NoError(err)

	tc := newTestClient(t, app)
	resp := tc.get("/auth/invite/" + token)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tc.getCSRF("/auth/invite/" + token)

	resp = tc.postForm("/auth/invite/"+token, url.Values{
		"username":  {"kim"},
		"first":     {"Kim"},
		"last":      {"Wexler"},
		"password":  {"NewSecret456!"},
		"password2": {"NewSecret456!"},
	}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// invited accounts are enabled immediately, email comes from the token
	u := fake.users["kim"]
	if assert.NotNil(u) {
		assert.False(u.Locked)
		assert.Equal("kim@example.com", u.Email)
		assert.Equal("", u.Category)
	}

	// token is single-use
	resp = tc.get("/auth/invite/" + token)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)

	// invited user can login right away
	tc2 := newTestClient(t, app)
	tc2.login("kim", "NewSecret456!")
}

func TestInviteGarbageToken(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newTestApp(t)

	tc := newTestClient(t, app)
	resp := tc.get("/auth/invite/garbage")
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)
}

func TestInviteSendRequiresAdmin(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
	})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("jesse", "Secret123!")

	resp := tc.postForm("/admin/invite", url.Values{"email": {"kim@example.com"}}, htmx)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
}

func TestEmailChangeConfirmFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Email: "old@example.com"})

	// token as SendEmailChangeConfirmEmail would issue it: claims.Email is
	// the NEW address
	token, err := NewToken("walter", "new@example.com", TokenEmailChange, router.storage)
	assert.NoError(err)

	tc := newTestClient(t, app)
	resp := tc.get("/auth/email/confirm/" + token)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tc.getCSRF("/auth/email/confirm/" + token)

	resp = tc.postForm("/auth/email/confirm/"+token, url.Values{}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("new@example.com", fake.users["walter"].Email)

	// token is single-use
	resp = tc.get("/auth/email/confirm/" + token)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)
}

func TestAccountSettingsEmailNotChangedDirectly(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Email: "old@example.com"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/account/settings", url.Values{
		"first": {"Walter"},
		"last":  {"White"},
		"email": {"attacker@example.com"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// email must stay until the confirmation link is used
	assert.Equal("old@example.com", fake.users["walter"].Email)
	assert.Equal("Walter", fake.users["walter"].First)
}

func TestAccountSettingsProfileFields(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.allow_change_shell", true)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Shell: "/bin/bash"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/account/settings", url.Values{
		"first":       {"Walter"},
		"last":        {"White"},
		"phone":       {"+1 505 555 0100"},
		"displayname": {"Heisenberg"},
		"telephone":   {"+1 505 555 0199"},
		"shell":       {"/bin/zsh"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	u := fake.users["walter"]
	assert.Equal("Heisenberg", u.DisplayName)
	assert.Equal("+1 505 555 0199", u.Telephone)
	assert.Equal("+1 505 555 0100", u.Mobile)
	assert.Equal("/bin/zsh", u.Shell)

	// a shell outside the allowlist is ignored
	resp = tc.postForm("/account/settings", url.Values{
		"first": {"Walter"},
		"last":  {"White"},
		"shell": {"/bin/evil"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("/bin/zsh", fake.users["walter"].Shell)
}

func TestAccountSettingsShellChangeDisabledByDefault(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!", Shell: "/bin/bash"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/account/settings", url.Values{
		"first": {"Walter"},
		"last":  {"White"},
		"shell": {"/bin/zsh"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("/bin/bash", fake.users["walter"].Shell)
}

func TestSSHKeyAddRequiresMFA(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.require_mfa", true)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!"}) // no OTP auth type

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/sshkey/add", url.Values{"key": {"ssh-ed25519 AAAA test"}}, htmx)
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
}
