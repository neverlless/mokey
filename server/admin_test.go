package server

import (
	"testing"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestIsAdmin(t *testing.T) {
	assert := assert.New(t)
	defer viper.Reset()

	user := &ipa.User{Username: "jdoe", Groups: []string{"ipausers"}}

	// disabled by default
	viper.Reset()
	assert.False(isAdmin(user))

	viper.Set("admin.enabled", true)
	viper.Set("admin.group", "admins")
	assert.False(isAdmin(user))

	user.Groups = []string{"ipausers", "admins"}
	assert.True(isAdmin(user))

	user.Groups = []string{"ipausers"}
	viper.Set("admin.users", []string{"jdoe"})
	assert.True(isAdmin(user))

	viper.Set("admin.users", []string{"other"})
	assert.False(isAdmin(user))
}

func TestAdminSubpagesRequireAdmin(t *testing.T) {
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("admin.enabled", true)
		viper.Set("admin.group", "admins")
	})
	fake.AddUser("jesse", ipatest.User{Password: "Secret123!"})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"admins"}})

	user := newTestClient(t, app)
	user.login("jesse", "Secret123!")
	for _, p := range []string{"/admin/people", "/admin/log"} {
		assert.Equal(t, fiber.StatusForbidden, user.get(p).StatusCode, p)
	}

	admin := newTestClient(t, app)
	admin.login("walter", "Secret123!")
	for p, id := range map[string]string{"/admin/people": `id="admin-users"`, "/admin/log": `id="admin-audit"`} {
		resp := admin.get(p)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode, p)
		assert.Contains(t, readBody(t, resp), id, p)
	}
	resp := admin.get("/admin")
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.NotContains(t, readBody(t, resp), `id="admin-users"`)
}
