// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gofiber/fiber/v2"
	"github.com/mileusna/useragent"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	ipa "github.com/ubccr/goipa"
)

const crlf = "\r\n"

type Emailer struct {
	templates     *template.Template
	storage       fiber.Storage
	slackNotifier *SlackNotifier
}

func BaseURL(ctx *fiber.Ctx) string {
	baseURL := viper.GetString("email.base_url")
	if baseURL == "" {
		baseURL = ctx.BaseURL()
	}

	return baseURL
}

func NewEmailer(storage fiber.Storage) (*Emailer, error) {
	tmpl := template.New("")
	tmpl.Funcs(funcMap)

	for _, ext := range []string{"txt", "html"} {
		var err error
		tmpl, err = tmpl.ParseFS(templateFiles, "templates/email/*."+ext)
		if err != nil {
			return nil, err
		}

		localTemplatePath := filepath.Join(viper.GetString("site.templates_dir"), "email/*."+ext)
		localTemplates, err := filepath.Glob(localTemplatePath)
		if err != nil {
			return nil, err
		}

		if len(localTemplates) > 0 {
			tmpl, err = tmpl.ParseGlob(localTemplatePath)
			if err != nil {
				return nil, err
			}
		}
	}

	return &Emailer{
		storage:       storage,
		templates:     tmpl,
		slackNotifier: NewSlackNotifier(),
	}, nil
}

func (e *Emailer) SendPasswordResetEmail(user *ipa.User, ctx *fiber.Ctx) error {
	token, err := NewToken(user.Username, user.Email, TokenPasswordReset, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/resetpw/%s", BaseURL(ctx), token),
		"link_expires": strings.TrimSpace(humanize.RelTime(time.Now(), time.Now().Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second), "", "")),
	}

	return e.sendEmail(user, ctx, T("email_template.password_reset_subject"), "password-reset", vars)
}

func (e *Emailer) SendAccountVerifyEmail(user *ipa.User, ctx *fiber.Ctx) error {
	token, err := NewToken(user.Username, user.Email, TokenAccountVerify, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/verify/%s", BaseURL(ctx), token),
		"link_expires": strings.TrimSpace(humanize.RelTime(time.Now(), time.Now().Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second), "", "")),
	}

	return e.sendEmail(user, ctx, T("email_template.account_verify_subject"), "account-verify", vars)
}

// SendEmailChangeConfirmEmail sends a confirmation link to the NEW email
// address. The change is only applied after the link is visited.
func (e *Emailer) SendEmailChangeConfirmEmail(user *ipa.User, newEmail string, ctx *fiber.Ctx) error {
	token, err := NewToken(user.Username, newEmail, TokenEmailChange, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/email/confirm/%s", BaseURL(ctx), token),
		"link_expires": strings.TrimSpace(humanize.RelTime(time.Now(), time.Now().Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second), "", "")),
		"new_email":    newEmail,
	}

	// deliver to the new address
	recipient := *user
	recipient.Email = newEmail

	return e.sendEmail(&recipient, ctx, T("email_template.email_change_subject"), "email-change", vars)
}

// SendEmailChangedNotification notifies the OLD address that the account
// email was changed.
func (e *Emailer) SendEmailChangedNotification(oldEmail string, user *ipa.User, ctx *fiber.Ctx) error {
	vars := map[string]interface{}{
		"event": T("email_template.email_changed_event"),
	}

	recipient := *user
	recipient.Email = oldEmail

	return e.sendEmail(&recipient, ctx, T("email_template.email_changed_event"), "account-updated", vars)
}

// SendInviteEmail sends an account invitation to an email address. The
// recipient completes their profile via the /auth/invite/:token link.
func (e *Emailer) SendInviteEmail(email string, ctx *fiber.Ctx) error {
	token, err := NewToken(email, email, TokenInvite, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/invite/%s", BaseURL(ctx), token),
		"link_expires": strings.TrimSpace(humanize.RelTime(time.Now(), time.Now().Add(time.Duration(viper.GetInt("email.token_max_age"))*time.Second), "", "")),
	}

	recipient := &ipa.User{Email: email}

	return e.sendEmail(recipient, ctx, T("email_template.invite_subject"), "invite", vars)
}

func (e *Emailer) SendWelcomeEmail(user *ipa.User, ctx *fiber.Ctx) error {
	vars := map[string]interface{}{
		"getting_started_url": viper.GetString("site.getting_started_url"),
	}

	subject := T("email_template.welcome_subject") + viper.GetString("site.name")

	return e.sendEmail(user, ctx, subject, "welcome", vars)
}

func (e *Emailer) SendMFAChangedEmail(enabled bool, user *ipa.User, ctx *fiber.Ctx) error {
	verb := T("email_template.two_factor_auth_disabled")
	if enabled {
		verb = T("email_template.two_factor_auth_enabled")
	}
	event := T("email_template.two_factor_auth_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, event, "account-updated", vars)
}

func (e *Emailer) SendPasskeyUpdatedEmail(added bool, user *ipa.User, ctx *fiber.Ctx) error {
	verb := T("email_template.passkey_removed")
	if added {
		verb = T("email_template.passkey_added")
	}
	event := T("email_template.passkey_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, event, "account-updated", vars)
}

func (e *Emailer) SendSSHKeyUpdatedEmail(added bool, user *ipa.User, ctx *fiber.Ctx) error {
	verb := T("email_template.ssh_key_removed")
	if added {
		verb = T("email_template.ssh_key_added")
	}
	event := T("email_template.ssh_key_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, event, "account-updated", vars)
}

func (e *Emailer) SendOTPTokenUpdatedEmail(added bool, user *ipa.User, ctx *fiber.Ctx) error {
	verb := T("email_template.otp_token_removed")
	if added {
		verb = T("email_template.otp_token_added")
	}
	event := T("email_template.otp_token_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, event, "account-updated", vars)
}

func (e *Emailer) SendPasswordChangedEmail(user *ipa.User, ctx *fiber.Ctx) error {
	vars := map[string]interface{}{
		"event": T("email_template.password_changed_event"),
	}

	return e.sendEmail(user, ctx, T("email_template.account_updated_subject"), "account-updated", vars)
}

func (e *Emailer) quotedBody(body []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	_, err := w.Write(body)
	if err != nil {
		return nil, err
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (e *Emailer) sendEmail(user *ipa.User, ctx *fiber.Ctx, subject, tmpl string, data map[string]interface{}) error {
	log.WithFields(log.Fields{
		"email":    user.Email,
		"username": user.Username,
	}).Debug("Sending email to user")

	if data == nil {
		data = make(map[string]interface{})
	}

	ua := useragent.Parse(ctx.Get(fiber.HeaderUserAgent))

	data["os"] = ua.OS
	data["browser"] = ua.Name
	data["user"] = user
	data["date"] = time.Now()
	data["contact"] = viper.GetString("email.from")
	data["sig"] = viper.GetString("email.signature")
	data["site_name"] = viper.GetString("site.name")
	data["help_url"] = viper.GetString("site.help_url")
	data["homepage"] = viper.GetString("site.homepage")
	data["base_url"] = BaseURL(ctx)

	var text bytes.Buffer
	err := e.templates.ExecuteTemplate(&text, tmpl+".txt", data)
	if err != nil {
		return err
	}

	txtBody, err := e.quotedBody(text.Bytes())
	if err != nil {
		return err
	}

	var html bytes.Buffer
	err = e.templates.ExecuteTemplate(&html, tmpl+".html", data)
	if err != nil {
		return err
	}

	htmlBody, err := e.quotedBody(html.Bytes())
	if err != nil {
		return err
	}

	header := make(textproto.MIMEHeader)
	header.Set("Mime-Version", "1.0")
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	header.Set("To", user.Email)
	header.Set("Subject", fmt.Sprintf("[%s] %s", viper.GetString("site.name"), subject))
	header.Set("From", viper.GetString("email.from"))

	var multipartBody bytes.Buffer
	mp := multipart.NewWriter(&multipartBody)
	header.Set("Content-Type", fmt.Sprintf("multipart/alternative;%s boundary=%s", crlf, mp.Boundary()))

	txtPart, err := mp.CreatePart(textproto.MIMEHeader(
		map[string][]string{
			"Content-Type":              []string{"text/plain; charset=utf-8"},
			"Content-Transfer-Encoding": []string{"quoted-printable"},
		}))
	if err != nil {
		return err
	}

	_, err = txtPart.Write(txtBody)
	if err != nil {
		return err
	}

	htmlPart, err := mp.CreatePart(textproto.MIMEHeader(
		map[string][]string{
			"Content-Type":              []string{"text/html; charset=utf-8"},
			"Content-Transfer-Encoding": []string{"quoted-printable"},
		}))
	if err != nil {
		return err
	}

	_, err = htmlPart.Write(htmlBody)
	if err != nil {
		return err
	}

	err = mp.Close()
	if err != nil {
		return err
	}

	smtpHostPort := net.JoinHostPort(viper.GetString("email.smtp_host"), strconv.Itoa(viper.GetInt("email.smtp_port")))
	var conn net.Conn
	tlsMode := viper.GetString("email.smtp_tls")

	switch tlsMode {
	case "on":
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         viper.GetString("email.smtp_host"),
		}
		conn, err = tls.Dial("tcp", smtpHostPort, tlsConfig)
	case "off", "starttls":
		conn, err = net.Dial("tcp", smtpHostPort)
	default:
		return fmt.Errorf("invalid config value for smtp_tls: %s", tlsMode)
	}

	if err != nil {
		return err
	}

	c, err := smtp.NewClient(conn, viper.GetString("email.smtp_host"))
	if err != nil {
		return err
	}
	defer c.Close()

	if tlsMode == "starttls" {
		err := c.StartTLS(&tls.Config{
			ServerName: viper.GetString("email.smtp_host"),
		})
		if err != nil {
			return err
		}
	}

	if viper.IsSet("email.smtp_username") && viper.IsSet("email.smtp_password") {
		auth := smtp.PlainAuth("", viper.GetString("email.smtp_username"), viper.GetString("email.smtp_password"), viper.GetString("email.smtp_host"))
		if err = c.Auth(auth); err != nil {
			log.Error(err)
			return err
		}
	}
	if err = c.Mail(viper.GetString("email.from")); err != nil {
		log.Error(err)
		return err
	}
	if err = c.Rcpt(user.Email); err != nil {
		log.Error(err)
		return err
	}

	wc, err := c.Data()
	if err != nil {
		return err
	}
	defer wc.Close()

	var buf bytes.Buffer
	for k, vv := range header {
		for _, v := range vv {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&buf, "\r\n")

	if _, err = buf.WriteTo(wc); err != nil {
		return err
	}
	if _, err = wc.Write(multipartBody.Bytes()); err != nil {
		return err
	}

	if e.slackNotifier != nil {
		var slackMessage string
		switch tmpl {
		case "password-reset":
			slackMessage = fmt.Sprintf(
				"[%s] (<%s|%s>)\n\n****************\nHi %s,\n****************\n\nYou recently requested to reset your password for your [%s] account. Use the link below to reset it. This password reset is only valid for the next %s.\n\nReset your password: <%s|Reset Link>\n",
				data["site_name"], data["homepage"], data["site_name"], user.First, data["site_name"], data["link_expires"], data["link"],
			)
		case "account-updated":
			slackMessage = "Your password has been reset successfully."
		default:
			slackMessage = fmt.Sprintf("Notification from %s: %s", data["site_name"], subject)
		}

		err = e.slackNotifier.SendSlackMessage(user.Email, slackMessage)
		if err != nil {
			log.WithFields(log.Fields{
				"email":    user.Email,
				"username": user.Username,
				"error":    err,
			}).Error("Failed to send Slack notification")
		}
	}

	return nil
}
