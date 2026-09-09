package server

// Delivery-path tests for #31: AUTH mechanism negotiation, the refusal to
// leak credentials over a plaintext link, and the server's verdict on the
// message actually reaching the caller.

import (
	"net/smtp"
	"net/url"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	ipa "github.com/ubccr/goipa"
)

func TestSMTPAuthMechanism(t *testing.T) {
	t.Run("prefers PLAIN when the server offers it", func(t *testing.T) {
		auth, err := smtpAuth("LOGIN PLAIN", "walter", "test-password", "mail.example.com", true)
		assert.NoError(t, err)
		proto, _, err := auth.Start(smtpServerInfo("mail.example.com", true, "LOGIN", "PLAIN"))
		assert.NoError(t, err)
		assert.Equal(t, "PLAIN", proto)
	})

	// the server in #31 answers AUTH PLAIN with 504
	t.Run("falls back to LOGIN when PLAIN is absent", func(t *testing.T) {
		auth, err := smtpAuth("NTLM LOGIN", "walter", "test-password", "mail.example.com", true)
		assert.NoError(t, err)
		proto, resp, err := auth.Start(smtpServerInfo("mail.example.com", true, "NTLM", "LOGIN"))
		assert.NoError(t, err)
		assert.Equal(t, "LOGIN", proto)
		assert.Empty(t, resp, "LOGIN sends no initial response")
	})

	t.Run("assumes PLAIN when the server advertises nothing", func(t *testing.T) {
		auth, err := smtpAuth("", "walter", "test-password", "mail.example.com", true)
		assert.NoError(t, err)
		proto, _, err := auth.Start(smtpServerInfo("mail.example.com", true))
		assert.NoError(t, err)
		assert.Equal(t, "PLAIN", proto)
	})

	t.Run("names the mechanisms when none is supported", func(t *testing.T) {
		_, err := smtpAuth("NTLM GSSAPI", "walter", "test-password", "mail.example.com", true)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "NTLM GSSAPI")
		}
	})

	// Go's PlainAuth refuses this too, but with a bare "unencrypted
	// connection" that says nothing about which knob to turn
	t.Run("refuses credentials over a plaintext link", func(t *testing.T) {
		_, err := smtpAuth("LOGIN", "walter", "test-password", "mail.example.com", false)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "smtp_tls")
		}
	})

	t.Run("allows a plaintext link to localhost", func(t *testing.T) {
		_, err := smtpAuth("LOGIN", "walter", "test-password", "127.0.0.1", false)
		assert.NoError(t, err)
	})
}

func TestLoginAuthChallenges(t *testing.T) {
	auth, err := smtpAuth("LOGIN", "walter", "test-password", "127.0.0.1", false)
	assert.NoError(t, err)
	if _, _, err := auth.Start(smtpServerInfo("127.0.0.1", false, "LOGIN")); err != nil {
		t.Fatalf("start: %s", err)
	}

	for _, tc := range []struct{ challenge, want string }{
		{"Username:", "walter"},
		{"username", "walter"},
		{"User Name\x00", "walter"},
		{"Password:", "test-password"},
		{"password", "test-password"},
	} {
		got, err := auth.Next([]byte(tc.challenge), true)
		assert.NoError(t, err, tc.challenge)
		assert.Equal(t, tc.want, string(got), tc.challenge)
	}

	if _, err := auth.Next([]byte("Domain:"), true); err == nil {
		t.Error("expected an error for an unknown challenge")
	}
}

// The reporter's server only offers NTLM and LOGIN; mokey used to send
// PLAIN regardless and get 504 back.
func TestSendEmailAuthenticatesWithLogin(t *testing.T) {
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
		viper.Set("email.smtp_username", "mokey")
		viper.Set("email.smtp_password", "test-smtp-password")
	})
	sink := newFakeSMTP(t)
	sink.authMechs = "NTLM LOGIN"
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/forgotpw")
	tc.postForm("/auth/forgotpw", url.Values{"username": {"walter"}}, nil)

	assert.Equal(t, 1, sink.count(), "message should have been delivered")
	user, pass := sink.credentials()
	assert.Equal(t, "mokey", user)
	assert.Equal(t, "test-smtp-password", pass)
}

// A message the server rejects at the final dot must not be reported as
// sent: the response to "." is where 250 or 5xx arrives.
func TestSendEmailSurfacesRejectionAtFinalDot(t *testing.T) {
	_, router, _ := newTestAppWith(t, nil)
	sink := newFakeSMTP(t)
	sink.rejectData = true

	err := router.emailer.SendPasswordResetEmail(&ipa.User{
		Username: "walter",
		Email:    "walter@example.com",
	}, nil)

	if assert.Error(t, err, "a rejected message must not report success") {
		assert.Contains(t, err.Error(), "550")
	}
	assert.Equal(t, 0, sink.count())
}

func TestSendEmailClosesTheSessionWithQuit(t *testing.T) {
	_, router, _ := newTestAppWith(t, nil)
	sink := newFakeSMTP(t)

	err := router.emailer.SendPasswordResetEmail(&ipa.User{
		Username: "walter",
		Email:    "walter@example.com",
	}, nil)

	assert.NoError(t, err)
	assert.True(t, sink.sawCommand("QUIT"), "session should end with QUIT")
}

// #31: the signup page told the user to check their inbox even when the
// verification mail never left. Nothing is leaked by saying so here — the
// account was just created by whoever is reading the page.
func TestSignupReportsFailedDelivery(t *testing.T) {
	app, _, _ := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
		viper.Set("accounts.enable_signup", true)
	})
	sink := newFakeSMTP(t)
	sink.rejectData = true

	tc := newTestClient(t, app)
	tc.getCSRF("/signup")
	resp := tc.postForm("/signup", url.Values{
		"first":     {"Walter"},
		"last":      {"White"},
		"username":  {"walter"},
		"email":     {"walter@example.com"},
		"password":  {"Secret123!"},
		"password2": {"Secret123!"},
	}, nil)
	body := readBody(t, resp)

	assert.Contains(t, body, T("signup_success.account_created"), "the account was still created")
	assert.Contains(t, body, T("common.email_send_failed"))
	assert.NotContains(t, body, T("common.check_email"))
}

// The counterpart: the flows that hide whether an account exists must keep
// rendering the same page when the send fails, or the failure itself
// becomes the enumeration oracle.
func TestForgotFlowsStayUniformWhenDeliveryFails(t *testing.T) {
	app, _, fake := newTestAppWith(t, func() {
		viper.Set("accounts.enable_captcha", false)
	})
	sink := newFakeSMTP(t)
	sink.rejectData = true
	fake.addUser("walter", &fakeUser{Password: "Secret123!"})

	tc := newTestClient(t, app)
	tc.getCSRF("/auth/forgotpw")

	known := readBody(t, tc.postForm("/auth/forgotpw", url.Values{"username": {"walter"}}, nil))
	unknown := readBody(t, tc.postForm("/auth/forgotpw", url.Values{"username": {"nobody"}}, nil))

	assert.Equal(t, unknown, known, "a delivery failure must not single out real accounts")
	assert.NotContains(t, known, T("common.email_send_failed"))
}

// smtpServerInfo builds the ServerInfo net/smtp hands to an Auth
func smtpServerInfo(name string, tls bool, mechs ...string) *smtp.ServerInfo {
	return &smtp.ServerInfo{Name: name, TLS: tls, Auth: mechs}
}
