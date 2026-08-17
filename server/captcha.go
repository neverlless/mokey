package server

import (
	"bytes"
	"errors"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v2"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// newCaptchaID returns a fresh captcha id, or "" when captchas are disabled
// (accounts.enable_captcha=false) — templates hide the captcha block for an
// empty id
func newCaptchaID() string {
	if !viper.GetBool("accounts.enable_captcha") {
		return ""
	}
	return captcha.New()
}

// Captcha handler displays captcha image
func (r *Router) Captcha(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	if c.FormValue("reload") != "" {
		captcha.Reload(id)
	}

	c.Append("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Append("Pragma", "no-cache")
	c.Append("Expires", "0")

	var content bytes.Buffer
	c.Append(fiber.HeaderContentType, "image/png")
	err := captcha.WriteImage(&content, id, captcha.StdWidth, captcha.StdHeight)
	if err != nil {
		log.WithFields(log.Fields{
			"id": id,
		}).Warn("Captcha not found")
		return c.Status(fiber.StatusNotFound).SendString("")
	}

	return c.SendStream(bytes.NewReader(content.Bytes()))
}

// Checks and verifies captcha

func (r *Router) verifyCaptcha(id, sol string) error {
	if !viper.GetBool("accounts.enable_captcha") {
		return nil
	}

	if len(id) == 0 {
		return errors.New("Invalid captcha provided")
	}
	if len(sol) == 0 {
		return errors.New("Please type in the numbers you see in the picture")
	}

	if !captcha.VerifyString(id, sol) {
		return errors.New("The numbers you typed in do not match the image")
	}

	return nil
}
