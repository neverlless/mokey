// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode"

	"github.com/gofiber/fiber/v2"
	"github.com/mileusna/useragent"
	ipa "github.com/neverlless/goipa"
	"github.com/spf13/viper"
)

const crlf = "\r\n"

type Emailer struct {
	templates     *template.Template
	byLang        map[string]*template.Template
	storage       fiber.Storage
	slackNotifier *SlackNotifier
}

func BaseURL(ctx *fiber.Ctx) string {
	baseURL := viper.GetString("email.base_url")
	if baseURL == "" && ctx != nil {
		baseURL = ctx.BaseURL()
	}

	return baseURL
}

func NewEmailer(storage fiber.Storage) (*Emailer, error) {
	tmpl := template.New("")
	tmpl.Funcs(funcMap).Funcs(template.FuncMap(languageFuncs(defaultLanguage())))

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

	byLang := make(map[string]*template.Template)
	for _, lang := range languages {
		clone, err := tmpl.Clone()
		if err != nil {
			return nil, err
		}
		byLang[lang] = clone.Funcs(template.FuncMap(languageFuncs(lang)))
	}

	return &Emailer{
		storage:       storage,
		templates:     tmpl,
		byLang:        byLang,
		slackNotifier: NewSlackNotifier(),
	}, nil
}

// emailLanguage is the request language for mail sent while serving one,
// else the recipient's preferred language.
func emailLanguage(user *ipa.User, ctx *fiber.Ctx) string {
	if ctx != nil {
		return requestLanguage(ctx)
	}
	return userLanguage(user)
}

func linkExpires(lang string) string {
	return formatDuration(lang, time.Duration(viper.GetInt("email.token_max_age"))*time.Second)
}

// sendTokenEmail delivers a mail carrying a single-use token, rolling back the
// "token issued" marker when delivery fails. Without the rollback a rejected or
// undeliverable address locks the user out of retrying until the token expires,
// every attempt failing with "token already issued".
func (e *Emailer) sendTokenEmail(user *ipa.User, tokenKey, prefix string, ctx *fiber.Ctx, lang, subject, tmpl string, data map[string]interface{}) error {
	err := e.sendEmail(user, ctx, lang, subject, tmpl, data)
	if err != nil {
		if derr := e.storage.Delete(prefix + TokenIssuedPrefix + tokenKey); derr != nil {
			slog.Error("Failed to roll back issued token marker after failed delivery",
				"username", user.Username,
				"err", derr,
			)
		}
	}
	return err
}

func (e *Emailer) SendPasswordResetEmail(user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	token, err := NewToken(user.Username, user.Email, TokenPasswordReset, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/resetpw/%s", BaseURL(ctx), token),
		"link_expires": linkExpires(lang),
	}

	return e.sendTokenEmail(user, user.Username, TokenPasswordReset, ctx, lang, TL(lang, "email_template.password_reset_subject"), "password-reset", vars)
}

// SendPasswordElsewhereEmail answers a reset request from a user whose
// password FreeIPA does not manage: reason says where it is managed.
func (e *Emailer) SendPasswordElsewhereEmail(user *ipa.User, reason string, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	// same resend cooldown as a reset link, so the form cannot flood the inbox
	marker := TokenPasswordReset + TokenIssuedPrefix + user.Username
	if sent, err := e.storage.Get(marker); err != nil || sent != nil {
		return err
	}
	if err := e.storage.Set(marker, []byte("true"), time.Duration(viper.GetInt("email.resend_cooldown"))*time.Second); err != nil {
		return err
	}
	return e.sendEmail(user, ctx, lang, TL(lang, "email_template.password_elsewhere_subject"), "password-elsewhere", map[string]interface{}{"reason": reason})
}

func (e *Emailer) SendAccountVerifyEmail(user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	token, err := NewToken(user.Username, user.Email, TokenAccountVerify, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/verify/%s", BaseURL(ctx), token),
		"link_expires": linkExpires(lang),
	}

	return e.sendTokenEmail(user, user.Username, TokenAccountVerify, ctx, lang, TL(lang, "email_template.account_verify_subject"), "account-verify", vars)
}

// SendOTPRecoveryConfirmEmail sends the confirm-before-queue link for an
// OTP lockout recovery request
func (e *Emailer) SendOTPRecoveryConfirmEmail(user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	token, err := NewToken(user.Username, user.Email, TokenOTPRecovery, e.storage)
	if err != nil {
		return err
	}
	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/otprecovery/%s", BaseURL(ctx), token),
		"link_expires": linkExpires(lang),
	}
	return e.sendTokenEmail(user, user.Username, TokenOTPRecovery, ctx, lang, TL(lang, "email_template.otprecovery_confirm_subject"), "otprecovery-confirm", vars)
}

// SendEmailChangeConfirmEmail sends a confirmation link to the NEW email
// address. The change is only applied after the link is visited.
func (e *Emailer) SendEmailChangeConfirmEmail(user *ipa.User, newEmail string, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	token, err := NewToken(user.Username, newEmail, TokenEmailChange, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/email/confirm/%s", BaseURL(ctx), token),
		"link_expires": linkExpires(lang),
		"new_email":    newEmail,
	}

	// deliver to the new address
	recipient := *user
	recipient.Email = newEmail

	return e.sendTokenEmail(&recipient, user.Username, TokenEmailChange, ctx, lang, TL(lang, "email_template.email_change_subject"), "email-change", vars)
}

// SendEmailChangedNotification notifies the OLD address that the account
// email was changed.
func (e *Emailer) SendEmailChangedNotification(oldEmail string, user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	vars := map[string]interface{}{
		"event": TL(lang, "email_template.email_changed_event"),
	}

	recipient := *user
	recipient.Email = oldEmail

	return e.sendEmail(&recipient, ctx, lang, TL(lang, "email_template.email_changed_event"), "account-updated", vars)
}

// SendInviteEmail sends an account invitation to an email address. The
// recipient completes their profile via the /auth/invite/:token link.
func (e *Emailer) SendInviteEmail(email string, ctx *fiber.Ctx) error {
	recipient := &ipa.User{Email: email}
	lang := emailLanguage(recipient, ctx)
	token, err := NewToken(email, email, TokenInvite, e.storage)
	if err != nil {
		return err
	}

	vars := map[string]interface{}{
		"link":         fmt.Sprintf("%s/auth/invite/%s", BaseURL(ctx), token),
		"link_expires": linkExpires(lang),
	}

	return e.sendTokenEmail(recipient, email, TokenInvite, ctx, lang, TL(lang, "email_template.invite_subject"), "invite", vars)
}

func (e *Emailer) SendWelcomeEmail(user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	vars := map[string]interface{}{
		"getting_started_url": viper.GetString("site.getting_started_url"),
	}

	subject := TL(lang, "email_template.welcome_subject") + viper.GetString("site.name")

	return e.sendEmail(user, ctx, lang, subject, "welcome", vars)
}

func (e *Emailer) SendMFAChangedEmail(enabled bool, user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	verb := TL(lang, "email_template.two_factor_auth_disabled")
	if enabled {
		verb = TL(lang, "email_template.two_factor_auth_enabled")
	}
	event := TL(lang, "email_template.two_factor_auth_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, lang, event, "account-updated", vars)
}

func (e *Emailer) SendPasskeyUpdatedEmail(added bool, user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	verb := TL(lang, "email_template.passkey_removed")
	if added {
		verb = TL(lang, "email_template.passkey_added")
	}
	event := TL(lang, "email_template.passkey_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, lang, event, "account-updated", vars)
}

func (e *Emailer) SendSSHKeyUpdatedEmail(added bool, user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	verb := TL(lang, "email_template.ssh_key_removed")
	if added {
		verb = TL(lang, "email_template.ssh_key_added")
	}
	event := TL(lang, "email_template.ssh_key_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, lang, event, "account-updated", vars)
}

func (e *Emailer) SendOTPTokenUpdatedEmail(added bool, user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	verb := TL(lang, "email_template.otp_token_removed")
	if added {
		verb = TL(lang, "email_template.otp_token_added")
	}
	event := TL(lang, "email_template.otp_token_event") + verb

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, ctx, lang, event, "account-updated", vars)
}

// SendNewLoginEmail notifies about a fresh sign-in. Called from a
// goroutine after the login response — no request context.
func (e *Emailer) SendNewLoginEmail(user *ipa.User, browser, os, ip string) error {
	lang := userLanguage(user)
	event := TL(lang, "email_template.new_login_event_part1") + browser + " (" + os + ")" +
		TL(lang, "email_template.new_login_event_part2") + ip

	vars := map[string]interface{}{
		"event": event,
	}

	return e.sendEmail(user, nil, lang, TL(lang, "email_template.new_login_subject"), "account-updated", vars)
}

// SendPasswordExpiryReminderEmail warns a user their password expires in
// the given number of days. Sent from the background sweep — no request
// context.
func (e *Emailer) SendPasswordExpiryReminderEmail(user *ipa.User, days int) error {
	lang := userLanguage(user)
	vars := map[string]interface{}{
		"days": days,
	}

	return e.sendEmail(user, nil, lang, TL(lang, "email_template.password_expiry_subject"), "password-expiry", vars)
}

// SendGroupRequestEmail notifies a group sponsor about a pending join or
// leave request. Called from a goroutine after the handler returns — no
// request context, mirrors SendNewLoginEmail.
func (e *Emailer) SendGroupRequestEmail(manager *ipa.User, requester, group, reqType string) error {
	lang := userLanguage(manager)
	vars := map[string]interface{}{
		"requester": requester,
		"group":     group,
		"type":      reqType,
	}

	subject := TL(lang, "email_template.group_request_subject")
	if reqType == groupRequestLeave {
		subject = TL(lang, "email_template.group_leave_request_subject")
	}
	return e.sendEmail(manager, nil, lang, subject+group, "group-request", vars)
}

// SendGroupDecisionEmail notifies the requester that a sponsor approved or
// denied their join or leave request. Called synchronously from
// GroupApprove/GroupDeny in the request path with a nil ctx, so the base
// URL comes from config rather than the request — mirrors
// SendNewLoginEmail's nil-ctx mechanism.
func (e *Emailer) SendGroupDecisionEmail(user *ipa.User, group string, approved bool, reqType string) error {
	lang := userLanguage(user)
	vars := map[string]interface{}{
		"group":    group,
		"approved": approved,
		"type":     reqType,
	}
	leave := reqType == groupRequestLeave
	subject := TL(lang, "email_template.group_denied_subject")
	switch {
	case approved && leave:
		subject = TL(lang, "email_template.group_leave_approved_subject")
	case !approved && leave:
		subject = TL(lang, "email_template.group_leave_denied_subject")
	case approved:
		subject = TL(lang, "email_template.group_approved_subject")
	}
	return e.sendEmail(user, nil, lang, subject+group, "group-decision", vars)
}

// SendGroupRemovedEmail notifies a member that a sponsor removed them from
// a group directly (not via a leave request they initiated).
func (e *Emailer) SendGroupRemovedEmail(user *ipa.User, group string) error {
	lang := userLanguage(user)
	vars := map[string]interface{}{
		"group": group,
	}
	return e.sendEmail(user, nil, lang, TL(lang, "email_template.group_removed_subject")+group, "group-removed", vars)
}

// SendOTPRecoveryDecisionEmail notifies the requester that an admin approved
// or denied their OTP recovery request. Called synchronously from
// AdminUserAction in the request path with a nil ctx, so the base URL comes
// from config rather than the request — mirrors SendGroupDecisionEmail.
func (e *Emailer) SendOTPRecoveryDecisionEmail(user *ipa.User, approved bool) error {
	lang := userLanguage(user)
	vars := map[string]interface{}{
		"approved": approved,
	}
	subject := TL(lang, "email_template.otprecovery_denied_subject")
	if approved {
		subject = TL(lang, "email_template.otprecovery_approved_subject")
	}
	return e.sendEmail(user, nil, lang, subject, "otprecovery-decision", vars)
}

// SendUsernameReminderEmail mails the username(s) associated with an address.
// The recipient is identified only by email — no account context is leaked in
// the delivery metadata.
func (e *Emailer) SendUsernameReminderEmail(email string, usernames []string, ctx *fiber.Ctx) error {
	recipient := &ipa.User{Email: email}
	lang := emailLanguage(recipient, ctx)
	vars := map[string]interface{}{
		"usernames": usernames,
	}

	return e.sendEmail(recipient, ctx, lang, TL(lang, "email_template.username_reminder_subject"), "username-reminder", vars)
}

func (e *Emailer) SendPasswordChangedEmail(user *ipa.User, ctx *fiber.Ctx) error {
	lang := emailLanguage(user, ctx)
	// Opt-in: password-change notification emails are off by default
	if !viper.GetBool("email.notify_password_change") {
		return nil
	}

	vars := map[string]interface{}{
		"event": TL(lang, "email_template.password_changed_event"),
	}

	return e.sendEmail(user, ctx, lang, TL(lang, "email_template.account_updated_subject"), "account-updated", vars)
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

// slackMessageFor builds the Slack DM text for a given email template. Most
// templates fall through to a generic notice; a few carry information (like
// the username list) that's worth surfacing directly in Slack rather than
// pointing the user at their email.
func slackMessageFor(tmpl, subject string, data map[string]interface{}, user *ipa.User) string {
	switch tmpl {
	case "password-reset":
		return fmt.Sprintf(
			"[%s] (<%s|%s>)\n\n****************\nHi %s,\n****************\n\nYou recently requested to reset your password for your [%s] account. Use the link below to reset it. This password reset is only valid for the next %s.\n\nReset your password: <%s|Reset Link>\n",
			data["site_name"], data["homepage"], data["site_name"], user.First, data["site_name"], data["link_expires"], data["link"],
		)
	case "account-updated":
		return "Your password has been reset successfully."
	case "password-elsewhere":
		return fmt.Sprintf("Notification from %s: %s\n\n%s", data["site_name"], subject, data["reason"])
	case "username-reminder":
		usernames, _ := data["usernames"].([]string)
		return fmt.Sprintf("Notification from %s: %s\n\n%s", data["site_name"], subject, strings.Join(usernames, "\n"))
	default:
		return fmt.Sprintf("Notification from %s: %s", data["site_name"], subject)
	}
}

func (e *Emailer) sendEmail(user *ipa.User, ctx *fiber.Ctx, lang, subject, tmpl string, data map[string]interface{}) error {
	slog.Debug("Sending email to user",
		"email", user.Email,
		"username", user.Username,
	)

	if data == nil {
		data = make(map[string]interface{})
	}

	// ctx is nil for emails sent from background jobs (expiry reminders)
	if ctx != nil {
		ua := useragent.Parse(ctx.Get(fiber.HeaderUserAgent))
		data["os"] = ua.OS
		data["browser"] = ua.Name
	} else {
		data["os"] = ""
		data["browser"] = ""
	}
	data["user"] = user
	data["date"] = time.Now()
	data["contact"] = viper.GetString("email.from")
	data["sig"] = viper.GetString("email.signature")
	data["site_name"] = viper.GetString("site.name")
	data["help_url"] = viper.GetString("site.help_url")
	data["homepage"] = viper.GetString("site.homepage")
	data["base_url"] = BaseURL(ctx)

	templates := e.templates
	if t, ok := e.byLang[lang]; ok {
		templates = t
	}

	var text bytes.Buffer
	err := templates.ExecuteTemplate(&text, tmpl+".txt", data)
	if err != nil {
		return err
	}

	txtBody, err := e.quotedBody(text.Bytes())
	if err != nil {
		return err
	}

	var html bytes.Buffer
	err = templates.ExecuteTemplate(&html, tmpl+".html", data)
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
	// Both affixes are configurable: some mail gateways only pass a message
	// when its subject carries a marker (ubccr/mokey#28). Unset keeps the
	// site-name prefix; setting it to "" removes the prefix entirely.
	prefix := fmt.Sprintf("[%s] ", viper.GetString("site.name"))
	if viper.IsSet("email.subject_prefix") {
		prefix = viper.GetString("email.subject_prefix")
	}
	header.Set("Subject", prefix+subject+viper.GetString("email.subject_suffix"))
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

	encrypted := false
	switch tlsMode {
	case "on":
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         viper.GetString("email.smtp_host"),
		}
		conn, err = tls.Dial("tcp", smtpHostPort, tlsConfig)
		encrypted = true
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
		encrypted = true
	}

	username := viper.GetString("email.smtp_username")
	password := viper.GetString("email.smtp_password")
	if username != "" && password != "" {
		_, advertised := c.Extension("AUTH")
		auth, err := smtpAuth(advertised, username, password, viper.GetString("email.smtp_host"), encrypted)
		if err != nil {
			slog.Error("SMTP auth setup failed", "err", err)
			return err
		}
		if err = c.Auth(auth); err != nil {
			slog.Error("SMTP AUTH failed", "err", err)
			return err
		}
	}
	if err = c.Mail(viper.GetString("email.from")); err != nil {
		slog.Error("SMTP MAIL FROM failed", "err", err)
		return err
	}
	if err = c.Rcpt(user.Email); err != nil {
		slog.Error("SMTP RCPT TO failed", "err", err)
		return err
	}

	wc, err := c.Data()
	if err != nil {
		return err
	}

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
		_ = wc.Close()
		return err
	}

	// closing the DATA writer sends the final dot and reads the server's
	// verdict: this is where a rejected message is reported, and dropping
	// it used to turn every rejection into a "sent successfully"
	if err = wc.Close(); err != nil {
		slog.Error("SMTP server rejected the message", "err", err)
		return err
	}

	if err := c.Quit(); err != nil {
		// the message was already accepted; a botched goodbye is not a
		// delivery failure
		slog.Warn("SMTP QUIT failed after the message was accepted", "err", err)
	}

	if e.slackNotifier != nil {
		err = e.slackNotifier.SendSlackMessage(user.Email, slackMessageFor(tmpl, subject, data, user))
		if err != nil {
			slog.Error("Failed to send Slack notification",
				"email", user.Email,
				"username", user.Username,
				"error", err,
			)
		}
	}

	return nil
}

// isLocalSMTPHost mirrors net/smtp's own localhost check: credentials may
// travel in the clear only when they never leave the machine.
func isLocalSMTPHost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}

// smtpAuth picks an AUTH mechanism from the ones the server advertised in
// its EHLO response. Go's net/smtp only ships PLAIN and CRAM-MD5, so LOGIN
// is implemented here for servers that offer no PLAIN (#31).
func smtpAuth(advertised, username, password, host string, encrypted bool) (smtp.Auth, error) {
	if !encrypted && !isLocalSMTPHost(host) {
		return nil, fmt.Errorf("refusing to send SMTP credentials over an unencrypted connection to %s: set email.smtp_tls to \"starttls\" or \"on\"", host)
	}

	mechs := strings.Fields(strings.ToUpper(advertised))

	switch {
	// a server that advertises nothing still usually takes PLAIN, and that
	// is what mokey has always sent
	case len(mechs) == 0 || slices.Contains(mechs, "PLAIN"):
		return smtp.PlainAuth("", username, password, host), nil
	case slices.Contains(mechs, "LOGIN"):
		return &loginAuth{username: username, password: password, host: host}, nil
	}

	return nil, fmt.Errorf("no SMTP AUTH mechanism in common: server offers %q, mokey supports PLAIN and LOGIN", advertised)
}

// loginAuth implements the non-standard but widely deployed AUTH LOGIN
// exchange, with the same plaintext refusal net/smtp applies to PLAIN.
type loginAuth struct {
	username, password, host string
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !isLocalSMTPHost(server.Name) {
		return "", nil, errors.New("refusing to send SMTP credentials over an unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}

	// servers word the prompts differently ("Username:", "User Name",
	// "Password:"), so match on the leading word only
	prompt := strings.ToLower(strings.TrimFunc(string(fromServer), func(r rune) bool {
		return !unicode.IsLetter(r)
	}))

	switch {
	case strings.HasPrefix(prompt, "user"):
		return []byte(a.username), nil
	case strings.HasPrefix(prompt, "pass"):
		return []byte(a.password), nil
	}

	return nil, fmt.Errorf("unexpected SMTP LOGIN challenge: %q", fromServer)
}
