package server

import (
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestOTPRecoveryRequestFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
	})
	fake.addUser("walter", &fakeUser{Password: "Secret123!", AuthTypes: []string{"otp"}})
	fake.addUser("jesse", &fakeUser{Password: "Secret123!"}) // no OTP

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/otprecovery")

	// OTP-gated user: generic success, confirm token issued
	resp := tc.postForm("/auth/otprecovery", url.Values{"username": {"walter"}}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)
	issued, _ := router.storage.Get(TokenOTPRecovery + TokenIssuedPrefix + "walter")
	assert.NotEmpty(issued)

	// non-OTP user: SAME page copy, nothing issued
	resp = tc.postForm("/auth/otprecovery", url.Values{"username": {"jesse"}}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal(body, readBody(t, resp))
	issued, _ = router.storage.Get(TokenOTPRecovery + TokenIssuedPrefix + "jesse")
	assert.Empty(issued)

	// unknown user: same page again
	resp = tc.postForm("/auth/otprecovery", url.Values{"username": {"nobody"}}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal(body, readBody(t, resp))

	// nothing queued yet — the queue fills only on confirm
	assert.Empty(router.loadOTPRecoveryRequests())

	// confirm link: GET renders, POST queues and marks the token used
	router.storage.Delete(TokenOTPRecovery + TokenIssuedPrefix + "walter")
	token, err := NewToken("walter", "walter@example.com", TokenOTPRecovery, router.storage)
	assert.NoError(err)
	tc2 := newTestClient(t, app)
	resp = tc2.get("/auth/otprecovery/" + token)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	tc2.getCSRF("/auth/otprecovery/" + token)
	resp = tc2.postForm("/auth/otprecovery/"+token, url.Values{}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	reqs := router.loadOTPRecoveryRequests()
	if assert.Len(reqs, 1) {
		assert.Equal("walter", reqs[0].Username)
	}

	// token is single-use
	resp = tc2.get("/auth/otprecovery/" + token)
	assert.Equal(fiber.StatusNotFound, resp.StatusCode)

	// a second confirmed request doesn't double-queue
	token2, _ := NewToken("walter", "walter@example.com", TokenOTPRecovery, router.storage)
	tc3 := newTestClient(t, app)
	tc3.getCSRF("/auth/otprecovery/" + token2)
	resp = tc3.postForm("/auth/otprecovery/"+token2, url.Values{}, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Len(router.loadOTPRecoveryRequests(), 1)
}
