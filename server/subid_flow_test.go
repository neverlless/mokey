package server

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestSubidDisabledByDefault(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// no subid section on the account page
	resp := tc.get("/account")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.NotContains(readBody(t, resp), "subid")

	// generate route is not registered
	resp = tc.postForm("/subid/generate", url.Values{}, htmx)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)
}

func TestSubidGenerateFlow(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_subid", true)
	})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// no range yet: account page offers the generate action
	resp := tc.get("/account")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), "/subid/generate")

	// generate allocates a range for the logged-in user
	resp = tc.postForm("/subid/generate", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	sub, ok := fake.SubID("walter")
	if assert.True(ok) {
		assert.Contains(readBody(t, resp), "2147483648")
	}

	// account page now shows the range instead of the button
	resp = tc.get("/account")
	body := readBody(t, resp)
	assert.Contains(body, "2147483648")
	assert.NotContains(body, "/subid/generate")

	// repeat generate does not allocate a second range and still renders
	// the existing one
	resp = tc.postForm("/subid/generate", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	subs, err := fake.ClientAs(keytabUser).SubIDFind(nil)
	assert.NoError(err)
	if assert.Len(subs, 1) {
		assert.Equal(sub.ID, subs[0].ID)
	}
	assert.Contains(readBody(t, resp), "2147483648")
}
