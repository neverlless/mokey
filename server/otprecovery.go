// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"encoding/json"
	"time"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// OTP recovery request queue: single storage key holding a JSON list,
// same durability as the session index (memory/sqlite3/redis).
// ponytail: no cross-instance lock — a concurrent removal loses at worst
// a redundant queue write; OTP recovery itself is idempotent.

const (
	otpRecoveryKey = "otprecovery"
	otpRecoveryTTL = 30 * 24 * time.Hour
)

type OTPRecoveryRequest struct {
	Username    string    `json:"username"`
	RequestedAt time.Time `json:"requested_at"`
}

func (r *Router) loadOTPRecoveryRequests() []OTPRecoveryRequest {
	raw, err := r.storage.Get(otpRecoveryKey)
	if err != nil || raw == nil {
		return nil
	}
	var reqs []OTPRecoveryRequest
	if err := json.Unmarshal(raw, &reqs); err != nil {
		return nil
	}
	return reqs
}

func (r *Router) saveOTPRecoveryRequests(reqs []OTPRecoveryRequest) {
	if len(reqs) == 0 {
		r.storage.Delete(otpRecoveryKey)
		return
	}
	raw, err := json.Marshal(reqs)
	if err != nil {
		return
	}
	r.storage.Set(otpRecoveryKey, raw, otpRecoveryTTL)
}

// addOTPRecoveryRequest queues a recovery request; false when already queued
func (r *Router) addOTPRecoveryRequest(username string) bool {
	reqs := r.loadOTPRecoveryRequests()
	for _, req := range reqs {
		if req.Username == username {
			return false
		}
	}
	r.saveOTPRecoveryRequests(append(reqs, OTPRecoveryRequest{Username: username, RequestedAt: time.Now()}))
	return true
}

// removeOTPRecoveryRequest drops a queued request; false when absent
func (r *Router) removeOTPRecoveryRequest(username string) bool {
	reqs := r.loadOTPRecoveryRequests()
	kept := reqs[:0]
	for _, req := range reqs {
		if req.Username != username {
			kept = append(kept, req)
		}
	}
	if len(kept) == len(reqs) {
		return false
	}
	r.saveOTPRecoveryRequests(kept)
	return true
}

// OTPRecoveryRequest renders and handles the "Lost OTP token?" form.
// Every POST outcome renders the same success page — unknown, blocked,
// and non-OTP accounts are indistinguishable from a real request.
func (r *Router) OTPRecoveryRequest(c *fiber.Ctx) error {
	if c.Method() == fiber.MethodGet {
		return c.Render("otprecovery-forgot.html", fiber.Map{"captchaID": newCaptchaID()})
	}

	if err := r.verifyCaptcha(c.FormValue("captcha_id"), c.FormValue("captcha_sol")); err != nil {
		c.Append("HX-Trigger", "{\"reloadCaptcha\":\""+captcha.New()+"\"}")
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}

	username := c.FormValue("username")
	generic := func() error { return c.Render("otprecovery-forgot-success.html", fiber.Map{}) }

	if isBlocked(username) {
		log.WithFields(log.Fields{"username": username}).Warn("AUDIT OTP recovery attempt for blocked username")
		return generic()
	}
	user, err := r.adminClient.UserShow(username)
	if err != nil {
		log.WithFields(log.Fields{"username": username}).Warn("AUDIT OTP recovery attempt for unknown username")
		return generic()
	}
	if user.Locked || !user.OTPOnly() {
		log.WithFields(log.Fields{"username": username}).Warn("AUDIT OTP recovery attempt for non-OTP or locked user")
		return generic()
	}

	if err := r.emailer.SendOTPRecoveryConfirmEmail(user, c); err != nil {
		log.WithFields(log.Fields{"username": username, "err": err}).Error("Failed to send OTP recovery confirm email")
	} else {
		log.WithFields(log.Fields{"username": username, "ip": RemoteIP(c)}).Info("AUDIT OTP recovery confirm email sent")
	}
	return generic()
}

// OTPRecoveryConfirm queues the recovery request after the emailed link
// is confirmed — mailbox possession is the identity proof
func (r *Router) OTPRecoveryConfirm(c *fiber.Ctx) error {
	token := c.Params("token")
	claims, err := ParseToken(token, TokenOTPRecovery, r.storage)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Debug("Invalid OTP recovery token")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if c.Method() == fiber.MethodGet {
		return c.Render("otprecovery-confirm.html", fiber.Map{"claims": claims})
	}

	r.storage.Set(TokenOTPRecovery+TokenUsedPrefix+token, []byte("true"), time.Until(claims.Timestamp.Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second)))
	// release the issued-token lock now that this request is confirmed and
	// queued, so a future recovery attempt isn't blocked until TTL expiry
	r.storage.Delete(TokenOTPRecovery + TokenIssuedPrefix + claims.Username)
	r.addOTPRecoveryRequest(claims.Username)
	log.WithFields(log.Fields{"username": claims.Username, "ip": RemoteIP(c)}).Info("AUDIT OTP recovery requested")
	return c.Render("otprecovery-submitted.html", fiber.Map{})
}
