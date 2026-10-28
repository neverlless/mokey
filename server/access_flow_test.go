// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/neverlless/goipa/ipatest"
	"github.com/stretchr/testify/assert"
)

func TestAccessPageSections(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)

	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"chemists"}})

	// applies via group
	fake.AddHBACRule("lab-access", ipatest.HBACRule{
		Description: "Lab SSH",
		Groups:      []string{"chemists"}, Hosts: []string{"lab.test.local"},
		Services: []string{"sshd"},
	})
	// applies via direct uid
	fake.AddHBACRule("walter-direct", ipatest.HBACRule{
		Users: []string{"walter"}, HostCategory: "all", ServiceCategory: "all",
	})
	// applies to everyone
	fake.AddHBACRule("allow-all", ipatest.HBACRule{UserCategory: "all", HostCategory: "all", ServiceCategory: "all"})
	// someone else's rule: hidden
	fake.AddHBACRule("dea-only", ipatest.HBACRule{Users: []string{"hank"}, Hosts: []string{"dea.test.local"}})
	// disabled: hidden
	fake.AddHBACRule("old-rule", ipatest.HBACRule{Disabled: true, UserCategory: "all"})

	fake.AddSudoRule("cook-sudo", ipatest.SudoRule{
		Groups:       []string{"chemists"},
		HostCategory: "all", AllowCommands: []string{"/usr/bin/systemctl"},
	})
	fake.AddSudoRule("dea-sudo", ipatest.SudoRule{Users: []string{"hank"}, CmdCategory: "all"})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.get("/access")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)

	assert.Contains(body, "lab-access")
	assert.Contains(body, "Lab SSH")
	assert.Contains(body, "walter-direct")
	assert.Contains(body, "allow-all")
	assert.NotContains(body, "dea-only")
	assert.NotContains(body, "old-rule")

	assert.Contains(body, "cook-sudo")
	assert.Contains(body, "/usr/bin/systemctl")
	assert.NotContains(body, "dea-sudo")

	// simulator form present
	assert.Contains(body, "/access/test")
	// nav tab present
	assert.Contains(body, "access-tab")
}

func TestAccessSimulator(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	dropAllowAll(t, fake)

	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Groups: []string{"chemists"}})
	fake.AddHBACRule("lab-access", ipatest.HBACRule{
		Groups: []string{"chemists"},
		Hosts:  []string{"lab.test.local"}, Services: []string{"sshd"},
	})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	// allow: matched rule is named
	resp := tc.postForm("/access/test", url.Values{"host": {"lab.test.local"}, "service": {"sshd"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)
	assert.Contains(body, "lab-access")
	assert.Contains(body, "access-granted")

	// deny
	resp = tc.postForm("/access/test", url.Values{"host": {"dea.test.local"}, "service": {"sshd"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), "access-denied")

	// service defaults to sshd when empty
	resp = tc.postForm("/access/test", url.Values{"host": {"lab.test.local"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), "access-granted")

	// empty host → 400
	resp = tc.postForm("/access/test", url.Values{"service": {"sshd"}}, htmx)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
}

func TestAccessSimulatorIgnoresUserField(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	dropAllowAll(t, fake)

	// hank has access, walter does not; walter must not be able to test as hank
	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	fake.AddUser("hank", ipatest.User{Password: "Secret123!"})
	fake.AddHBACRule("dea-only", ipatest.HBACRule{
		Users: []string{"hank"},
		Hosts: []string{"dea.test.local"}, Services: []string{"sshd"},
	})

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.postForm("/access/test", url.Values{
		"host": {"dea.test.local"}, "service": {"sshd"}, "user": {"hank"},
	}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	// the session user (walter) is tested, not the form's "user" value
	assert.Contains(readBody(t, resp), "access-denied")
}
