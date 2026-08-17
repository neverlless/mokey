package server

import (
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var sidPattern = regexp.MustCompile(`"sid": "([^"]+)"`)

func securityPage(t *testing.T, tc *testClient) string {
	t.Helper()
	resp := tc.get("/security/settings", htmx)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	return readBody(t, resp)
}

func TestSessionListAndRevoke(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc1 := newTestClient(t, app)
	tc1.login("walter", "Secret123!")
	tc2 := newTestClient(t, app)
	tc2.login("walter", "Secret123!")

	// both sessions listed, current marked, the other one revocable
	body := securityPage(t, tc1)
	assert.Contains(body, "This device")
	sids := sidPattern.FindAllStringSubmatch(body, -1)
	if !assert.Len(sids, 1, "exactly one revocable (non-current) session expected") {
		return
	}
	otherSID := sids[0][1]

	// revoke the other session: it is logged out, this one survives
	resp := tc1.postForm("/security/session/revoke", url.Values{"sid": {otherSID}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	resp = tc2.get("/")
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	resp = tc1.get("/")
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// only one session remains listed
	assert.NotContains(securityPage(t, tc1), otherSID)
}

func TestSessionRevokeForeignSIDIgnored(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})

	tcWalter := newTestClient(t, app)
	tcWalter.login("walter", "Secret123!")

	// jesse learns walter's sid somehow — revocation must be a no-op
	// because it's not in jesse's index
	body := securityPage(t, tcWalter)
	_ = body
	tcJesse := newTestClient(t, app)
	tcJesse.login("jesse", "Secret123!")

	// walter's own current sid isn't in his page (only non-current are),
	// so grab it via a second walter session
	tcWalter2 := newTestClient(t, app)
	tcWalter2.login("walter", "Secret123!")
	sids := sidPattern.FindAllStringSubmatch(securityPage(t, tcWalter2), -1)
	if !assert.Len(sids, 1) {
		return
	}
	walterSID := sids[0][1]

	resp := tcJesse.postForm("/security/session/revoke", url.Values{"sid": {walterSID}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	// walter's session is untouched
	resp = tcWalter.get("/")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}

func TestSignOutOtherSessions(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc1 := newTestClient(t, app)
	tc1.login("walter", "Secret123!")
	tc2 := newTestClient(t, app)
	tc2.login("walter", "Secret123!")
	tc3 := newTestClient(t, app)
	tc3.login("walter", "Secret123!")

	resp := tc1.postForm("/security/sessions/revoke-others", url.Values{}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)

	for _, tc := range []*testClient{tc2, tc3} {
		resp = tc.get("/")
		assert.Equal(fiber.StatusFound, resp.StatusCode)
	}
	resp = tc1.get("/")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
}

func TestLogoutDropsSessionFromIndex(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc1 := newTestClient(t, app)
	tc1.login("walter", "Secret123!")
	tc2 := newTestClient(t, app)
	tc2.login("walter", "Secret123!")

	resp := tc2.postForm("/auth/logout", url.Values{}, nil)
	assert.Equal(fiber.StatusFound, resp.StatusCode)

	// only the current session remains — nothing revocable
	body := securityPage(t, tc1)
	assert.Len(sidPattern.FindAllStringSubmatch(body, -1), 0)
	assert.Contains(body, "This device")
}

func TestLoginHistoryOnSecurityPage(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"})

	// a failed and a successful login for walter, plus noise from jesse
	tcFail := newTestClient(t, app)
	tcFail.getCSRF("/auth/login")
	tcFail.postForm("/auth/authenticate", url.Values{
		"username": {"walter"}, "password": {"wrong"},
	}, nil)

	tcJesse := newTestClient(t, app)
	tcJesse.login("jesse", "Secret123!")

	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	body := securityPage(t, tc)
	assert.Contains(body, "Recent account activity")
	assert.Contains(body, "User logged in successfully")
	assert.Contains(body, "Failed login attempt")
}

func TestNewLoginEmailOptIn(t *testing.T) {
	assert := assert.New(t)
	app, _, fake := newTestApp(t)
	sink := newFakeSMTP(t)
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	// default: no email on login
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	time.Sleep(200 * time.Millisecond)
	assert.Equal(0, sink.count())

	// opt-in: one email per fresh login (sent async)
	viper.Set("email.notify_new_login", true)
	tc2 := newTestClient(t, app)
	tc2.login("walter", "Secret123!")
	deadline := time.Now().Add(3 * time.Second)
	for sink.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if assert.Equal(1, sink.count()) {
		assert.Contains(sink.all()[0], "New sign-in")
	}
}
