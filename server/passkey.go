// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
)

const SessionKeyWebAuthn = "webauthn_registration"

// passkeyUser adapts a mokey user to the webauthn.User interface. FreeIPA is
// the credential store, so no existing credentials are exposed.
type passkeyUser struct {
	username    string
	displayName string
}

func (u *passkeyUser) WebAuthnID() []byte                         { return []byte(u.username) }
func (u *passkeyUser) WebAuthnName() string                       { return u.username }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return nil }

func (r *Router) webAuthn(c *fiber.Ctx) (*webauthn.WebAuthn, error) {
	host := c.Hostname()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: T("passkey.rp_display_name"),
		RPID:          host,
		RPOrigins:     []string{c.BaseURL()},
	})
}

func (r *Router) passkeyList(c *fiber.Ctx) ([]fiber.Map, error) {
	mappings, err := userPasskeys(r.userClient(c), r.username(c))
	if err != nil {
		return nil, err
	}

	list := make([]fiber.Map, 0, len(mappings))
	for _, m := range mappings {
		id := strings.TrimPrefix(m, "passkey:")
		if i := strings.Index(id, ","); i > 0 {
			id = id[:i]
		}
		if len(id) > 16 {
			id = id[:16] + "…"
		}
		list = append(list, fiber.Map{"mapping": m, "shortid": id})
	}

	return list, nil
}

func (r *Router) PasskeyBegin(c *fiber.Ctx) error {
	w, err := r.webAuthn(c)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Failed to init webauthn")
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	user := &passkeyUser{username: r.username(c), displayName: r.user(c).DisplayName}

	options, sessionData, err := w.BeginRegistration(user)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "username": user.username}).Error("Failed to begin passkey registration")
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	sd, err := json.Marshal(sessionData)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	sess, err := r.session(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}
	sess.Set(SessionKeyWebAuthn, string(sd))
	if err := r.sessionSave(c, sess); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	return c.JSON(options)
}

func (r *Router) PasskeyFinish(c *fiber.Ctx) error {
	username := r.username(c)

	sess, err := r.session(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	sd, _ := sess.Get(SessionKeyWebAuthn).(string)
	if sd == "" {
		return c.Status(fiber.StatusBadRequest).SendString(T("passkey.registration_failed"))
	}
	sess.Delete(SessionKeyWebAuthn)
	r.sessionSave(c, sess)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sd), &sessionData); err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(T("passkey.registration_failed"))
	}

	pcc, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(c.Body()))
	if err != nil {
		log.WithFields(log.Fields{"err": err, "username": username}).Error("Failed to parse passkey registration response")
		return c.Status(fiber.StatusBadRequest).SendString(T("passkey.registration_failed"))
	}

	w, err := r.webAuthn(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	user := &passkeyUser{username: username, displayName: r.user(c).DisplayName}

	cred, err := w.CreateCredential(user, sessionData, pcc)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "username": username}).Error("Failed to verify passkey registration")
		return c.Status(fiber.StatusBadRequest).SendString(T("passkey.registration_failed"))
	}

	mapping, err := passkeyMapping(cred.ID, cred.PublicKey)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "username": username}).Error("Failed to build passkey mapping")
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	if err := userAddPasskey(r.userClient(c), username, mapping); err != nil {
		log.WithFields(log.Fields{"err": err, "username": username}).Error("Failed to add passkey in FreeIPA")
		return c.Status(fiber.StatusInternalServerError).SendString(T("passkey.freeipa_add_failed"))
	}

	log.WithFields(log.Fields{
		"username": username,
		"ip":       RemoteIP(c),
	}).Info("AUDIT passkey added successfully")

	if err := r.emailer.SendPasskeyUpdatedEmail(true, r.user(c), c); err != nil {
		log.WithFields(log.Fields{"err": err, "username": username}).Error("Failed to send passkey added email")
	}

	return c.SendStatus(fiber.StatusOK)
}

func (r *Router) PasskeyRemove(c *fiber.Ctx) error {
	username := r.username(c)
	mapping := c.FormValue("mapping")

	if !strings.HasPrefix(mapping, "passkey:") {
		return c.Status(fiber.StatusBadRequest).SendString("")
	}

	if err := userRemovePasskey(r.userClient(c), username, mapping); err != nil {
		log.WithFields(log.Fields{"err": err, "username": username}).Error("Failed to remove passkey in FreeIPA")
		return c.Status(fiber.StatusInternalServerError).SendString(T("passkey.freeipa_remove_failed"))
	}

	log.WithFields(log.Fields{
		"username": username,
		"ip":       RemoteIP(c),
	}).Info("AUDIT passkey removed successfully")

	if err := r.emailer.SendPasskeyUpdatedEmail(false, r.user(c), c); err != nil {
		log.WithFields(log.Fields{"err": err, "username": username}).Error("Failed to send passkey removed email")
	}

	passkeys, err := r.passkeyList(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(T("account.fatal_system_error"))
	}

	return c.Render("passkey-list.html", fiber.Map{
		"user":     r.user(c),
		"passkeys": passkeys,
	})
}
