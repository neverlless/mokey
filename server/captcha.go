package server

import (
	"bytes"
	"errors"
	"log/slog"

	"github.com/dchest/captcha"
	"github.com/gofiber/fiber/v3"
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
func (r *Router) Captcha(c fiber.Ctx) error {
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
		slog.Warn("Captcha not found",
			"id", id,
		)
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

const captchaPrefix = "captcha-"

// storageCaptchaStore keeps captchas in mokey's storage, so with redis a
// captcha shown by one replica verifies on any other
type storageCaptchaStore struct{ lock *storeLock }

func (s storageCaptchaStore) Set(id string, digits []byte) {
	if err := s.lock.storage.Set(captchaPrefix+id, digits, captcha.Expiration); err != nil {
		slog.Error("Failed to store captcha", "err", err)
	}
}

func (s storageCaptchaStore) Get(id string, clear bool) []byte {
	var digits []byte
	var err error
	if clear {
		digits, err = s.lock.take(captchaPrefix + id)
	} else {
		digits, err = s.lock.storage.Get(captchaPrefix + id)
	}
	if err != nil {
		// fail closed: a captcha that cannot be used up must not verify
		slog.Error("Failed to read captcha", "err", err)
		return nil
	}
	return digits
}
