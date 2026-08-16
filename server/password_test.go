package server

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestPasswordCheck(t *testing.T) {
	viper.Set("accounts.min_passwd_len", 8)
	viper.Set("accounts.min_passwd_classes", 3)

	assert := assert.New(t)

	// Too short
	assert.Error(checkPassword("123"))
	// Not enough classes
	assert.Error(checkPassword("123456789"))
	// Not enough classes
	assert.Error(checkPassword("test1234"))

	// Good
	assert.NoError(checkPassword("test!1234"))
}

// Semantics must match FreeIPA's util/ipa_pwd.c (ubccr/mokey#170)
func TestPasswordCheckMatchesFreeIPA(t *testing.T) {
	viper.Set("accounts.min_passwd_len", 8)
	viper.Set("accounts.min_passwd_classes", 4)

	assert := assert.New(t)

	// 4 classes, a doubled character ("ss") — FreeIPA only penalizes runs
	// of 3+, so this must pass
	assert.NoError(checkPassword("Password1!"))
	// 4 classes, tripled character — penalized down to 3, must fail
	assert.Error(checkPassword("Passsword1!"))
	// 4 classes via the 8-bit category (lower, upper, digit, non-ASCII)
	assert.NoError(checkPassword("aBcdef17п"))
	// only 3 classes at min 4 — fail
	assert.Error(checkPassword("abcdef17x"))

	viper.Set("accounts.min_passwd_classes", 5)
	// all 5 FreeIPA categories present
	assert.NoError(checkPassword("aB1!пxyz"))
}
