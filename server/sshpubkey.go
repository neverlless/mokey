package server

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
)

func (r *Router) SSHKeyList(c fiber.Ctx) error {
	user := r.user(c)
	vars := fiber.Map{
		"user": user,
	}
	return c.Render("sshkey-list.html", vars)
}

func (r *Router) SSHKeyModal(c fiber.Ctx) error {
	vars := fiber.Map{}
	return c.Render("sshkey-new.html", vars)
}

func (r *Router) SSHKeyAdd(c fiber.Ctx) error {
	user := r.user(c)

	title := c.FormValue("title")
	key := c.FormValue("key")

	if key == "" {
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, "sshkey_new.provide_key"))
	}

	authKey, err := ipa.NewSSHAuthorizedKey(key)
	if err != nil {
		slog.Error("Failed to add new ssh key",
			"username", user.Username,
			"err", err,
		)
		return c.Status(fiber.StatusBadRequest).SendString(TC(c, "sshkey_new.invalid_key"))
	}

	if title != "" {
		// TODO validate title
		authKey.Comment = title
	}

	user.AddSSHAuthorizedKey(authKey)

	user, err = r.adminClient.UserMod(user)
	if err != nil {
		return err
	}

	c.Locals(ContextKeyUser, user)

	err = r.emailer.SendSSHKeyUpdatedEmail(true, user, c)
	if err != nil {
		slog.Error("Failed to send sshkey added email",
			"err", err,
			"username", user.Username,
		)
	}

	return r.SSHKeyList(c)
}

func (r *Router) SSHKeyRemove(c fiber.Ctx) error {
	fp := c.FormValue("fp")
	user := r.user(c)

	user.RemoveSSHAuthorizedKey(fp)

	var err error
	user, err = r.adminClient.UserMod(user)
	if err != nil {
		return err
	}

	c.Locals(ContextKeyUser, user)

	err = r.emailer.SendSSHKeyUpdatedEmail(false, user, c)
	if err != nil {
		slog.Error("Failed to send sshkey removed email",
			"err", err,
			"username", user.Username,
		)
	}

	return r.SSHKeyList(c)
}
