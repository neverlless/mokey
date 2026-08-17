package server

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestExpiryBannerAndPolicyDisplay(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{
		Password:     "Secret123!",
		PasswdExpire: time.Now().Add(5 * 24 * time.Hour),
	})
	fake.addUser("jesse", &fakeUser{
		Password:     "Secret123!",
		PasswdExpire: time.Now().Add(60 * 24 * time.Hour),
	})

	// expiring within the warning window: banner on every portal page
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	resp := tc.get("/")
	body := readBody(t, resp)
	assert.Contains(body, "Your password expires in ")
	assert.Contains(body, "Change it now")

	// password change form shows the effective FreeIPA policy
	resp = tc.get("/password/change", htmx)
	body = readBody(t, resp)
	assert.Contains(body, "Password requirements")
	assert.Contains(body, "at least 8 characters")
	assert.Contains(body, "expires every 90 days")

	// far from expiry: no banner
	tc2 := newTestClient(t, app)
	tc2.login("jesse", "Secret123!")
	resp = tc2.get("/")
	assert.NotContains(readBody(t, resp), "Your password expires in ")
}

func TestPasswordExpiryReminderSweep(t *testing.T) {
	assert := assert.New(t)
	_, router, fake := newTestApp(t)
	sink := newFakeSMTP(t)

	// configured after app build so the background goroutine never starts —
	// the sweep is driven manually here
	viper.Set("email.password_expiry_reminders", []int{14, 7, 3})

	now := time.Now()
	fake.addUser("walter", &fakeUser{Password: "Secret123!", PasswdExpire: now.Add(5 * 24 * time.Hour)})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!", PasswdExpire: now.Add(60 * 24 * time.Hour)})
	fake.addUser("skyler", &fakeUser{Password: "Secret123!", Locked: true, PasswdExpire: now.Add(2 * 24 * time.Hour)})
	fake.addUser("gus", &fakeUser{Password: "Secret123!"}) // no expiry set

	router.expiryReminderSweep()

	// only walter qualifies: inside the 7-day window, not locked, has expiry
	msgs := sink.all()
	if assert.Len(msgs, 1) {
		assert.Contains(msgs[0], "walter@example.com")
		assert.Contains(msgs[0], "expires soon")
	}

	// re-running the sweep must not send duplicates
	router.expiryReminderSweep()
	assert.Equal(1, sink.count())

	// crossing into a tighter window sends the next reminder
	fake.users["walter"].PasswdExpire = now.Add(2 * 24 * time.Hour)
	router.expiryReminderSweep()
	assert.Equal(2, sink.count())

	// none of the emails went to anyone but walter
	for _, m := range sink.all() {
		assert.False(strings.Contains(m, "jesse@") || strings.Contains(m, "skyler@") || strings.Contains(m, "gus@"))
	}
}
