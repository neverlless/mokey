package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	ipa "github.com/ubccr/goipa"
)

func TestSlackMessageForUsernameReminderIncludesUsernames(t *testing.T) {
	assert := assert.New(t)
	user := &ipa.User{First: "Walter"}
	data := map[string]interface{}{
		"site_name": "Test",
		"usernames": []string{"walter", "heisenberg"},
	}

	msg := slackMessageFor("username-reminder", "Your username", data, user)

	assert.Contains(msg, "walter")
	assert.Contains(msg, "heisenberg")
}
