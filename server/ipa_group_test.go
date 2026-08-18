package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	ipa "github.com/ubccr/goipa"
)

// userSession logs a fake user in through goipa and returns the client
func userSession(t *testing.T, fake *fakeIPA, username, password string) *ipa.Client {
	t.Helper()
	client := fake.client()
	err := client.RemoteLogin(username, password)
	assert.NoError(t, err)
	return client
}

// swapRPCHTTPClient points ipaSessionRPC's direct HTTP client at the fake's
// TLS cert and returns a func to restore the original client
func swapRPCHTTPClient(f *fakeIPA) (restore func()) {
	orig := ipaRPCHTTPClient
	ipaRPCHTTPClient = f.srv.Client()
	return func() { ipaRPCHTTPClient = orig }
}

func TestGroupRPCLayer(t *testing.T) {
	assert := assert.New(t)
	fake := newFakeIPA()
	defer fake.Close()

	restore := swapRPCHTTPClient(fake)
	defer restore()

	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})
	fake.addGroup("chemists", &fakeGroup{
		Description:  "Lab crew",
		ManagerUsers: []string{"walter"},
	})
	fake.addGroup("plain", &fakeGroup{}) // no managers: not joinable

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
}
