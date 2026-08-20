package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	hydra "github.com/ory/hydra-client-go/v26"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type FakeTLSTransport struct {
	T http.RoundTripper
}

// connectedApp is one OAuth client the user has granted consent to, shown
// on the Security page.
type connectedApp struct {
	ClientID  string
	Name      string
	Scope     []string
	GrantedAt time.Time
}

// listConnectedApps lists the caller's granted OAuth clients via Hydra's
// admin API. r.hydraClient must be non-nil (Hydra configured).
func (r *Router) listConnectedApps(username string) ([]connectedApp, error) {
	sessions, _, err := r.hydraClient.OAuth2API.ListOAuth2ConsentSessions(context.Background()).Subject(username).Execute()
	if err != nil {
		return nil, err
	}

	apps := []connectedApp{}
	for _, s := range sessions {
		app := connectedApp{Scope: s.GrantScope}
		if s.HandledAt != nil {
			app.GrantedAt = *s.HandledAt
		}
		if cr := s.ConsentRequest; cr != nil && cr.Client != nil {
			app.ClientID = cr.Client.GetClientId()
			app.Name = cr.Client.GetClientName()
			if app.Name == "" {
				app.Name = app.ClientID
			}
		}
		apps = append(apps, app)
	}
	return apps, nil
}

// revokeConnectedApp revokes one client's consent for the caller.
func (r *Router) revokeConnectedApp(username, clientID string) error {
	_, err := r.hydraClient.OAuth2API.RevokeOAuth2ConsentSessions(context.Background()).
		Subject(username).Client(clientID).Execute()
	return err
}

func (ftt *FakeTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("X-Forwarded-Proto", "https")
	return ftt.T.RoundTrip(req)
}

func (r *Router) ConsentGet(c *fiber.Ctx) error {
	// Get the challenge from the query.
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		log.WithFields(log.Fields{
			"ip": RemoteIP(c),
		}).Error("Consent endpoint was called without a consent challenge")
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusBadRequest).SendString(T("hydra.consent_without_challenge"))
	}

	consent, _, err := r.hydraClient.OAuth2API.GetOAuth2ConsentRequest(context.Background()).
		ConsentChallenge(challenge).Execute()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the consent challenge")
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.failed_to_validate_consent"))
	}

	subject := consent.GetSubject()

	user, err := r.adminClient.UserShow(subject)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"username": subject,
		}).Warn("Failed to find User record for consent")
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.failed_to_validate_consent"))
	}

	if viper.GetBool("accounts.require_mfa") && !user.OTPOnly() {
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusUnauthorized).SendString(T("hydra.access_denied"))
	}

	acceptBody := hydra.NewAcceptOAuth2ConsentRequest()
	acceptBody.SetGrantScope(consent.GetRequestedScope())
	session := hydra.NewAcceptOAuth2ConsentRequestSession()
	session.SetIdToken(map[string]interface{}{
		"uid":                user.Username,
		"preferred_username": user.Username,
		"name":               user.DisplayName,
		"first":              user.First,
		"last":               user.Last,
		"given_name":         user.First,
		"family_name":        user.Last,
		"groups":             user.Groups,
		"email":              user.Email,
	})
	acceptBody.SetSession(*session)

	redirect, _, err := r.hydraClient.OAuth2API.AcceptOAuth2ConsentRequest(context.Background()).
		ConsentChallenge(challenge).AcceptOAuth2ConsentRequest(*acceptBody).Execute()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to accept the consent challenge")
		r.metrics.totalHydraFailedLogins.Inc()
		return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.failed_to_accept_consent"))
	}

	log.WithFields(log.Fields{
		"username": subject,
	}).Info("AUDIT User logged in via Hydra OAuth2 successfully")
	r.metrics.totalHydraLogins.Inc()

	c.Set("HX-Redirect", redirect.GetRedirectTo())
	return c.Redirect(redirect.GetRedirectTo())
}

func (r *Router) LoginOAuthGet(c *fiber.Ctx) error {
	// Get the challenge from the query.
	challenge := c.Query("login_challenge")
	if challenge == "" {
		log.WithFields(log.Fields{
			"ip": RemoteIP(c),
		}).Error("Login OAuth endpoint was called without a challenge")
		return c.Status(fiber.StatusBadRequest).SendString(T("hydra.login_without_challenge"))
	}

	login, _, err := r.hydraClient.OAuth2API.GetOAuth2LoginRequest(context.Background()).
		LoginChallenge(challenge).Execute()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Failed to validate the login challenge")
		return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.failed_to_validate_login"))
	}

	if login.GetSkip() {
		subject := login.GetSubject()

		log.WithFields(log.Fields{
			"user": subject,
		}).Debug("Hydra requested we skip login")

		// Check to make sure we have a valid user id
		user, err := r.adminClient.UserShow(subject)
		if err != nil {
			log.WithFields(log.Fields{
				"error":    err,
				"username": subject,
			}).Warn("Failed to find User record for login")
			r.metrics.totalHydraFailedLogins.Inc()
			return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.failed_to_validate_login"))
		}

		if viper.GetBool("accounts.require_mfa") && !user.OTPOnly() {
			r.metrics.totalHydraFailedLogins.Inc()
			return c.Status(fiber.StatusUnauthorized).SendString(T("hydra.access_denied"))
		}

		redirect, _, err := r.hydraClient.OAuth2API.AcceptOAuth2LoginRequest(context.Background()).
			LoginChallenge(challenge).
			AcceptOAuth2LoginRequest(*hydra.NewAcceptOAuth2LoginRequest(subject)).Execute()
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("Failed to accept the GET login challenge")
			r.metrics.totalHydraFailedLogins.Inc()
			return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.failed_to_accept_login"))
		}

		log.WithFields(log.Fields{
			"username": subject,
		}).Debug("Hydra OAuth login GET challenge signed successfully")

		c.Set("HX-Redirect", redirect.GetRedirectTo())
		return c.Redirect(redirect.GetRedirectTo())
	}

	if ok, _ := r.isLoggedIn(c); ok {
		return r.LoginOAuthPost(r.username(c), challenge, c)
	}

	vars := fiber.Map{
		"challenge": challenge,
	}

	return c.Render("login.html", vars)
}

func (r *Router) LoginOAuthPost(username, challenge string, c *fiber.Ctx) error {
	acceptBody := hydra.NewAcceptOAuth2LoginRequest(username)
	acceptBody.SetRemember(true) // TODO: make this configurable
	acceptBody.SetRememberFor(viper.GetInt64("hydra.login_timeout"))

	redirect, _, err := r.hydraClient.OAuth2API.AcceptOAuth2LoginRequest(context.Background()).
		LoginChallenge(challenge).AcceptOAuth2LoginRequest(*acceptBody).Execute()
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"error":    err,
		}).Error("Failed to accept the POST login challenge")
		return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.failed_to_accept_login"))
	}

	log.WithFields(log.Fields{
		"username": username,
	}).Debug("Hydra OAuth2 login POST challenge signed successfully")

	if c.Get("HX-Request", "false") == "true" {
		c.Set("HX-Redirect", redirect.GetRedirectTo())
		return c.Status(fiber.StatusNoContent).SendString("")
	}

	return c.Redirect(redirect.GetRedirectTo())
}

func (r *Router) HydraError(c *fiber.Ctx) error {
	message := c.Query("error")
	desc := c.Query("error_description")
	hint := c.Query("error_hint")

	log.WithFields(log.Fields{
		"message": message,
		"desc":    desc,
		"hint":    hint,
	}).Error("OAuth2 request failed")

	return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.oauth2_error"))
}

// HydraLogout implements the Hydra OIDC logout flow. Hydra redirects the
// user here with a logout_challenge; we destroy the local session, accept
// the challenge, and redirect the user back (e.g. to the client's
// post_logout_redirect_uri). See https://www.ory.sh/docs/hydra/concepts/logout
func (r *Router) HydraLogout(c *fiber.Ctx) error {
	challenge := c.Query("logout_challenge")

	logoutRequest, _, err := r.hydraClient.OAuth2API.GetOAuth2LogoutRequest(context.Background()).
		LogoutChallenge(challenge).Execute()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"ip":    RemoteIP(c),
		}).Error("Failed to validate hydra logout challenge")
		return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.failed_to_validate_logout"))
	}

	// Destroy the local mokey session (also revokes the user's hydra
	// authentication sessions when a session cookie is present)
	r.logout(c)

	redirect, _, err := r.hydraClient.OAuth2API.AcceptOAuth2LogoutRequest(context.Background()).
		LogoutChallenge(challenge).Execute()
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"ip":    RemoteIP(c),
		}).Error("Failed to accept hydra logout request")
		return c.Status(fiber.StatusInternalServerError).SendString(T("hydra.failed_to_accept_logout"))
	}

	log.WithFields(log.Fields{
		"subject": logoutRequest.GetSubject(),
		"ip":      RemoteIP(c),
	}).Info("Completed hydra logout flow")

	return c.Redirect(redirect.GetRedirectTo())
}

func (r *Router) revokeHydraAuthenticationSession(username string) error {
	_, err := r.hydraClient.OAuth2API.RevokeOAuth2LoginSessions(context.Background()).
		Subject(username).Execute()
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"user": username,
	}).Info("Successfully revoked hydra authentication session")

	return nil
}
