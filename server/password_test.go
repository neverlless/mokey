package server

import (
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestPasswordCheck(t *testing.T) {
	viper.Set("accounts.min_passwd_len", 8)
	viper.Set("accounts.min_passwd_classes", 3)

	assert := assert.New(t)

	// Too short
	assert.Error(checkPassword("123", "", nil))
	// Not enough classes
	assert.Error(checkPassword("123456789", "", nil))
	// Not enough classes
	assert.Error(checkPassword("test1234", "", nil))

	// Good
	assert.NoError(checkPassword("test!1234", "", nil))
}

// Semantics must match FreeIPA's util/ipa_pwd.c (ubccr/mokey#170)
func TestPasswordCheckMatchesFreeIPA(t *testing.T) {
	viper.Set("accounts.min_passwd_len", 8)
	viper.Set("accounts.min_passwd_classes", 4)

	assert := assert.New(t)

	// 4 classes, a doubled character ("ss") — FreeIPA only penalizes runs
	// of 3+, so this must pass
	assert.NoError(checkPassword("Password1!", "", nil))
	// 4 classes, tripled character — penalized down to 3, must fail
	assert.Error(checkPassword("Passsword1!", "", nil))
	// 4 classes via the 8-bit category (lower, upper, digit, non-ASCII)
	assert.NoError(checkPassword("aBcdef17п", "", nil))
	// only 3 classes at min 4 — fail
	assert.Error(checkPassword("abcdef17x", "", nil))

	viper.Set("accounts.min_passwd_classes", 5)
	// all 5 FreeIPA categories present
	assert.NoError(checkPassword("aB1!пxyz", "", nil))
}

// Measured against FreeIPA 4.13.4 with libpwquality 1.4.4 via
// /ipa/session/change_password; these cases are the contract
func TestPasswordCheckPwquality(t *testing.T) {
	viper.Set("accounts.min_passwd_len", 0)
	viper.Set("accounts.min_passwd_classes", 0)

	cases := []struct {
		policy PwPolicy
		user   string
		ok     []string
		bad    map[string]string
	}{
		{PwPolicy{MinLength: 10, DigitCredit: 2}, "", []string{"abcdefg12", "abcdefgh12"},
			map[string]string{"abcdefg1": fmt.Sprintf(T("password.min_length"), 10)}},
		{PwPolicy{MinLength: 8, DigitCredit: -2}, "", []string{"abcdefg12"},
			map[string]string{"abcdefgh1": T("password.too_few_digits")}},
		{PwPolicy{MinLength: 8, UpperCredit: -1, LowerCredit: -1, OtherCredit: -1}, "", []string{"Abcdefg!"},
			map[string]string{
				"abcdefgh": T("password.too_few_upper"),
				"Abcdefgh": T("password.too_few_special"),
				"ABCDEFG!": T("password.too_few_lower"),
			}},
		{PwPolicy{MinLength: 6, MaxRepeat: 2}, "", []string{"aabbccdd"},
			map[string]string{
				"aaabbbcc": T("password.too_many_repeats"),
				"xyAAA9q":  T("password.too_many_repeats"),
				"abccba":   T("password.palindrome"),
				"Ab1221bA": T("password.palindrome"),
				"Abccba":   T("password.palindrome"),
				"aBc1cbA":  T("password.palindrome"),
			}},
		{PwPolicy{MinLength: 6, MaxSequence: 3}, "", []string{"qabcwxz", "qACEGwz", "qxyzaw", "xzaBcDw"},
			map[string]string{
				"qabcdwz": T("password.sequence"),
				"q4321wz": T("password.sequence"),
				"q1234wz": T("password.sequence"),
				"qABCDwz": T("password.sequence"),
			}},
		{PwPolicy{MinLength: 6, UserCheck: true}, "heisenberg", []string{"heisen12"},
			map[string]string{
				"xxheisenbergxx": T("password.contains_username"),
				"xxHeisenBergxx": T("password.contains_username"),
				"grebnesieh12":   T("password.contains_username"),
			}},
		{PwPolicy{MinLength: 6, UserCheck: true}, "walt", nil,
			map[string]string{
				"xxwaltxx": T("password.contains_username"),
				"xxtlawxx": T("password.contains_username"),
			}},
		{PwPolicy{MinLength: 6, UserCheck: true}, "pwq", []string{"xxpwqxx"}, nil},
		// libpwquality's dictionary check is FreeIPA's alone
		{PwPolicy{MinLength: 6, DictCheck: true}, "", []string{"password", "elephant", "Elephant1"}, nil},
	}
	for _, tc := range cases {
		for _, pass := range tc.ok {
			assert.NoError(t, checkPassword(pass, tc.user, &tc.policy), "%+v %q", tc.policy, pass)
		}
		for pass, msg := range tc.bad {
			assert.EqualError(t, checkPassword(pass, tc.user, &tc.policy), msg, "%+v %q", tc.policy, pass)
		}
	}

	// without libpwquality options the plain length applies, credits or not
	assert.Error(t, checkPassword("abcdefg12", "", &PwPolicy{MinLength: 10}))
	assert.NoError(t, checkPassword("abccba", "", &PwPolicy{MinLength: 6}))
}
