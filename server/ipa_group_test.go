package server

import (
	"github.com/neverlless/goipa/ipatest"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/stretchr/testify/assert"
)

// userSession logs a fake user in through goipa and returns the client
func userSession(t *testing.T, fake *ipatest.Server, username, password string) *ipa.Client {
	t.Helper()
	client := newFakeClient(fake)
	err := client.RemoteLogin(username, password)
	assert.NoError(t, err)
	return client
}

func TestGroupRPCLayer(t *testing.T) {
	assert := assert.New(t)
	fake := ipatest.NewServer(t)

	fake.AddUser("walter", ipatest.User{Password: "Secret123!"})
	fake.AddUser("jesse", ipatest.User{Password: "Secret123!"})
	fake.AddGroup("chemists", ipatest.Group{
		Description:  "Lab crew",
		ManagerUsers: []string{"walter"},
	})
	fake.AddGroup("plain", ipatest.Group{}) // no managers: not joinable

	sponsor := userSession(t, fake, "walter", "Secret123!")

	groups, err := groupFindManaged(sponsor)
	assert.NoError(err)
	if assert.Len(groups, 1) {
		assert.Equal("chemists", groups[0].Name)
		assert.Equal("Lab crew", groups[0].Description)
		assert.Equal([]string{"walter"}, groups[0].ManagerUsers)
	}

	g, err := groupShow(sponsor, "chemists")
	assert.NoError(err)
	assert.Equal("chemists", g.Name)

	// sponsor adds a member with their own session
	assert.NoError(groupAddMember(sponsor, "chemists", "jesse"))
	g, _ = groupShow(sponsor, "chemists")
	assert.Contains(g.Members, "jesse")

	// non-manager is rejected by the fake's permission check
	outsider := userSession(t, fake, "jesse", "Secret123!")
	assert.Error(groupAddMember(outsider, "plain", "jesse"))

	// sponsor removes a member with their own session
	assert.NoError(groupRemoveMember(sponsor, "chemists", "jesse"))
	g, _ = groupShow(sponsor, "chemists")
	assert.NotContains(g.Members, "jesse")

	// non-manager is rejected by the fake's permission check
	assert.NoError(groupAddMember(sponsor, "chemists", "jesse"))
	err = groupRemoveMember(outsider, "chemists", "jesse")
	if assert.Error(err) {
		assert.Contains(err.Error(), "Insufficient access")
	}

	// already in the wanted state: FreeIPA refuses, mokey treats it as done
	assert.NoError(groupAddMember(sponsor, "chemists", "jesse"))
	assert.NoError(groupRemoveMember(sponsor, "chemists", "jesse"))
	assert.NoError(groupRemoveMember(sponsor, "chemists", "jesse"))
}
