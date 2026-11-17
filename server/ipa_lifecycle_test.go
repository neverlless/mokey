package server

import (
	"testing"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/stretchr/testify/assert"
)

const walterDN = "uid=walter,cn=users,cn=accounts,dc=test,dc=local"

func TestUserSponsor(t *testing.T) {
	for name, tc := range map[string]struct {
		manager any
		want    string
	}{
		"plain uid": {[]string{"walter"}, "walter"},
		"dn":        {[]string{walterDN}, "walter"},
		"upper dn":  {[]string{"UID=walter,cn=users,dc=test"}, "walter"},
		"other dn":  {[]string{"cn=admins,cn=groups,cn=accounts,dc=test,dc=local"}, ""},
		"none":      {nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			fake := ipatest.NewServer(t)
			fake.Handle("user_show", func(c ipatest.Call) (any, *ipa.IpaError) {
				assert.Equal(t, true, c.Options["all"])
				e := map[string]any{"uid": []string{"jesse"}}
				if tc.manager != nil {
					e["manager"] = tc.manager
				}
				return map[string]any{"result": e}, nil
			})
			got, err := userSponsor(fake.ClientAs("admin"), "jesse")
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func lastMod(t *testing.T, fake *ipatest.Server) ipatest.Call {
	t.Helper()
	calls := fake.Calls()
	if len(calls) == 0 || calls[len(calls)-1].Method != "user_mod" {
		t.Fatalf("last call is not user_mod: %v", calls)
	}
	return calls[len(calls)-1]
}

func TestSetSponsorAndExpiryWire(t *testing.T) {
	fake := ipatest.NewServer(t)
	fake.Handle("user_mod", func(ipatest.Call) (any, *ipa.IpaError) {
		return map[string]any{"result": map[string]any{}}, nil
	})
	admin := fake.ClientAs("admin")

	assert.NoError(t, setUserSponsor(admin, "jesse", "walter"))
	c := lastMod(t, fake)
	assert.Equal(t, []string{"jesse"}, c.Args)
	assert.Equal(t, "walter", c.Options["manager"])

	assert.NoError(t, setUserSponsor(admin, "jesse", ""))
	assert.Equal(t, "", lastMod(t, fake).Options["manager"])

	at := time.Date(2027, 11, 16, 3, 4, 5, 0, time.FixedZone("x", 7200))
	assert.NoError(t, setUserExpiry(admin, "jesse", at))
	c = lastMod(t, fake)
	assert.Equal(t, "20271116010405Z", c.Options["krbprincipalexpiration"])

	assert.NoError(t, setUserExpiry(admin, "jesse", time.Time{}))
	assert.Equal(t, "", lastMod(t, fake).Options["krbprincipalexpiration"])
}

func TestSetUserExpiryEmptyModlistIsNotAnError(t *testing.T) {
	fake := ipatest.NewServer(t)
	fake.Handle("user_mod", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: 4202, Message: "no modifications to be performed"}
	})
	assert.NoError(t, setUserExpiry(fake.ClientAs("admin"), "jesse", time.Time{}))
	assert.NoError(t, setUserSponsor(fake.ClientAs("admin"), "jesse", ""))
}

func TestSponsoredBy(t *testing.T) {
	fake := ipatest.NewServer(t)
	fake.Handle("user_find", func(c ipatest.Call) (any, *ipa.IpaError) {
		assert.Equal(t, "walter", c.Options["manager"])
		assert.Equal(t, true, c.Options["all"])
		assert.Equal(t, float64(0), c.Options["sizelimit"])
		assert.Equal(t, float64(0), c.Options["timelimit"])
		return map[string]any{"result": []map[string]any{{"uid": []string{"jesse"}}}, "count": 1}, nil
	})
	users, err := sponsoredBy(fake.ClientAs("admin"), "walter")
	assert.NoError(t, err)
	if assert.Len(t, users, 1) {
		assert.Equal(t, "jesse", users[0].Username)
	}
}
