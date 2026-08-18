// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestAccessPageSections(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)

	fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: []string{"chemists"}})

	// applies via group
	fake.addHBACRule("lab-access", &fakeHBACRule{
		Enabled: true, Description: "Lab SSH",
		MemberGroups: []string{"chemists"}, MemberHosts: []string{"lab.test.local"},
		MemberServices: []string{"sshd"},
	})
	// applies via direct uid
	fake.addHBACRule("walter-direct", &fakeHBACRule{
		Enabled: true, MemberUsers: []string{"walter"}, HostCategory: "all", ServiceCategory: "all",
	})
	// applies to everyone
	fake.addHBACRule("allow-all", &fakeHBACRule{Enabled: true, UserCategory: "all", HostCategory: "all", ServiceCategory: "all"})
	// someone else's rule: hidden
	fake.addHBACRule("dea-only", &fakeHBACRule{Enabled: true, MemberUsers: []string{"hank"}, MemberHosts: []string{"dea.test.local"}})
	// disabled: hidden
	fake.addHBACRule("old-rule", &fakeHBACRule{Enabled: false, UserCategory: "all"})

	fake.addSudoRule("cook-sudo", &fakeSudoRule{
		Enabled: true, MemberGroups: []string{"chemists"},
		HostCategory: "all", AllowCommands: []string{"/usr/bin/systemctl"},
	})
	fake.addSudoRule("dea-sudo", &fakeSudoRule{Enabled: true, MemberUsers: []string{"hank"}, CmdCategory: "all"})

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
