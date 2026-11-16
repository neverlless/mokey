package server

import (
	"errors"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestFAAccess(t *testing.T) {
	_, router, fake := newTestApp(t)
	fake.AddGroup("scientists", ipatest.Group{MemberGroups: []string{"chemists"}})
	fake.AddUser("walter", ipatest.User{Groups: []string{"chemists"}})
	fake.AddUser("hank", ipatest.User{})
	fake.AddUser("gone", ipatest.User{Locked: true})
	fake.AddUser("otp", ipatest.User{AuthTypes: []string{"otp"}})
	fake.AddHost("app.example.com", ipatest.Host{})
	fake.AddHBACRule("allow_all", ipatest.HBACRule{Disabled: true})
	fake.AddHBACRule("app-rule", ipatest.HBACRule{Users: []string{"walter"}, Hosts: []string{"app.example.com"}, Services: []string{"sshd"}})

	cases := []struct {
		name   string
		user   string
		app    faApp
		cfg    map[string]any
		allow  bool
		reason string
	}{
		{"empty groups = any", "hank", faApp{}, nil, true, ""},
		{"direct group", "walter", faApp{Groups: []string{"chemists"}}, nil, true, ""},
		{"case-insensitive", "walter", faApp{Groups: []string{"Chemists"}}, nil, true, ""},
		{"nested group", "walter", faApp{Groups: []string{"scientists"}}, nil, true, ""},
		{"not in group", "hank", faApp{Groups: []string{"scientists"}}, nil, false, "not_in_group"},
		{"locked", "gone", faApp{}, nil, false, "disabled"},
		{"missing", "nobody", faApp{}, nil, false, "no_user"},
		{"blocked", "hank", faApp{}, map[string]any{"accounts.block_users": []string{"hank"}}, false, "blocked"},
		{"mfa missing", "hank", faApp{}, map[string]any{"accounts.require_mfa": true}, false, "mfa_required"},
		{"mfa ok", "otp", faApp{}, map[string]any{"accounts.require_mfa": true}, true, ""},
		{"hbac granted", "walter", faApp{Host: "app.example.com", HBACService: "sshd"}, nil, true, ""},
		{"hbac denied", "hank", faApp{Host: "app.example.com", HBACService: "sshd"}, nil, false, "hbac_denied"},
		{"hbac host override", "walter", faApp{Host: "other.example.com", HBACHost: "app.example.com", HBACService: "sshd"}, nil, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.cfg {
				viper.Set(k, v)
				t.Cleanup(func() { viper.Set(k, nil) })
			}
			d, err := router.faAccess(tc.user, tc.app)
			assert.NoError(t, err)
			assert.Equal(t, tc.allow, d.Allowed)
			assert.Equal(t, tc.reason, d.Reason)
			if tc.user == "walter" {
				assert.ElementsMatch(t, []string{"chemists", "scientists"}, d.Groups)
			}
		})
	}
}

func TestFAAccessFreeIPAError(t *testing.T) {
	_, router, fake := newTestApp(t)
	fake.Handle("user_show", func(ipatest.Call) (any, *ipa.IpaError) {
		return nil, &ipa.IpaError{Code: 4301, Message: "boom"}
	})
	_, err := router.faAccess("walter", faApp{})
	assert.Error(t, err)
	assert.False(t, errors.Is(err, ipa.ErrNotFound))
}
