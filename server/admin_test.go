package server

import (
	"testing"

	ipa "github.com/neverlless/goipa"
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
