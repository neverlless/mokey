package server

import (
	"testing"

	"github.com/neverlless/goipa"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// isEmail replaced govalidator.IsEmail; these are the answers govalidator gave
func TestIsEmail(t *testing.T) {
	for _, tt := range []struct {
		email string
		want  bool
	}{
		{"walter@example.com", true},
		{"Walter.White@Example.COM", true},
		{"a+tag@sub.example.org", true},
		{"first.last@example.co.uk", true},
		{"o'brien@example.ie", true},
		{"a!#$%&'*+-/=?^_`{|}~@example.com", true},
		{"user@xn--bcher-kva.de", true},
		{"user@bücher.de", true},
		{"jürgen@example.de", true},
		{"user@123.com", true},
		{"x@y.z", true},
		{"", false},
		{"plain", false},
		{"@example.com", false},
		{"user@", false},
		{"user@localhost", false},
		{"user@-example.com", false},
		{"user@example-.com", false},
		{"user@example.c0m", true},
		{"user@example.123", false},
		{"user@1.2.3.4", false},
		{"user@[1.2.3.4]", false},
		{"user@example..com", false},
		{"user@exa!mple.com", false},
		{".user@example.com", false},
		{"us..er@example.com", false},
		{"user name@example.com", false},
		{"Walter <walter@example.com>", false},
		{"<walter@example.com>", false},
		{" walter@example.com", false},
		{"walter@example.com\n", false},
		{"a@b@example.com", false},
		// govalidator accepted a trailing root dot; FreeIPA mail addresses never carry one
		{"user@example.com.", false},
	} {
		assert.Equal(t, tt.want, isEmail(tt.email), "%q", tt.email)
	}
}

func TestValidateUsernameRejectsAllDigits(t *testing.T) {
	t.Cleanup(viper.Reset)
	err := validateUsername(&ipa.User{Username: "12345", Email: "a@example.com"})
	assert.EqualError(t, err, "Username must include at least one letter")
	assert.NoError(t, validateUsername(&ipa.User{Username: "a12345", Email: "a@example.com"}))
}

func TestUsernameFromEmail(t *testing.T) {
	assert := assert.New(t)

	allowedDomains := map[string]string{
		"example.edu": "default",
		"example.com": "flast",
	}

	type testUsername struct {
		test   string
		result string
	}

	goodTests := []testUsername{
		testUsername{"user@example.edu", "user"},
		testUsername{"user123@example.edu", "user123"},
		testUsername{"user.test@example.edu", "user.test"},
		testUsername{"user-test@example.edu", "user-test"},
		testUsername{"user@test@example.edu", "usertest"},
		testUsername{"user+test@example.edu", "usertest"},
		testUsername{"first.last@example.com", "flast"},
		testUsername{".last@example.com", "last"},
	}

	for _, utest := range goodTests {
		user := &ipa.User{Email: utest.test}
		err := generateUsernameFromEmail(user, allowedDomains)
		if assert.NoError(err) {
			assert.Equal(utest.result, user.Username)
		}
	}

	badTests := []testUsername{
		testUsername{"user@invalidemail.edu", ""},
		testUsername{"@example.edu", ""},
	}

	for _, utest := range badTests {
		user := &ipa.User{Email: utest.test}
		err := generateUsernameFromEmail(user, allowedDomains)
		assert.Error(err)
	}

}
