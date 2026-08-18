package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccessRPCLayer(t *testing.T) {
	assert := assert.New(t)
	fake := newFakeIPA()
	defer fake.Close()
	restore := swapRPCHTTPClient(fake)
	defer restore()

	fake.addUser("walter", &fakeUser{Password: "Secret123!", Groups: []string{"chemists"}})
	fake.addHBACRule("lab-access", &fakeHBACRule{
		Enabled:        true,
		MemberGroups:   []string{"chemists"},
		MemberHosts:    []string{"lab.test.local"},
		MemberServices: []string{"sshd"},
	})
	fake.addHBACRule("disabled-rule", &fakeHBACRule{Enabled: false, UserCategory: "all"})
	fake.addSudoRule("run-all", &fakeSudoRule{
		Enabled:      true,
		MemberUsers:  []string{"walter"},
		HostCategory: "all",
		CmdCategory:  "all",
	})

	client := userSession(t, fake, "walter", "Secret123!")

	hbac, hbacTruncated, err := hbacRuleFind(client)
	assert.NoError(err)
	assert.Len(hbac, 2)
	assert.False(hbacTruncated)
	byName := map[string]*hbacRule{}
	for _, r := range hbac {
		byName[r.Name] = r
	}
	assert.True(byName["lab-access"].Enabled)
	assert.False(byName["disabled-rule"].Enabled)
	assert.Equal([]string{"chemists"}, byName["lab-access"].MemberGroups)
	assert.Equal([]string{"sshd"}, byName["lab-access"].MemberServices)

	sudo, sudoTruncated, err := sudoRuleFind(client)
	assert.NoError(err)
	assert.False(sudoTruncated)
	if assert.Len(sudo, 1) {
		assert.Equal("run-all", sudo[0].Name)
		assert.Equal("all", sudo[0].CmdCategory)
	}

	// simulator: group-matched rule grants sshd on the lab host
	res, err := hbacTest(client, "walter", "lab.test.local", "sshd")
	assert.NoError(err)
	assert.True(res.Granted)
	assert.Contains(res.Matched, "lab-access")

	// wrong service is denied
	res, err = hbacTest(client, "walter", "lab.test.local", "ftp")
	assert.NoError(err)
	assert.False(res.Granted)

	// applicability helper
	assert.True(ruleAppliesToUser("all", nil, nil, "x", nil))
	assert.True(ruleAppliesToUser("", []string{"walter"}, nil, "walter", nil))
	assert.True(ruleAppliesToUser("", nil, []string{"chemists"}, "walter", []string{"chemists"}))
	assert.False(ruleAppliesToUser("", []string{"jesse"}, []string{"lab"}, "walter", []string{"chemists"}))
}
