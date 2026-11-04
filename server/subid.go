// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
)

// subidVars adds the user's subordinate id range (nil when none) to the
// template vars. On a fetch error the section stays hidden rather than
// offering a generate button on top of unknown state.
func (r *Router) subidVars(username string, vars fiber.Map) {
	sub, err := subidFind(r.adminClient, username)
	if err != nil {
		slog.Error("Failed to fetch subordinate id range",
			"username", username,
			"err", err,
		)
		return
	}
	vars["subid_enabled"] = true
	vars["subid"] = sub
}

// SubidGenerate allocates the subordinate id range for the logged-in user
// and re-renders the subid card. Generation is one-shot per user; a
// duplicate error just renders the existing range.
func (r *Router) SubidGenerate(c fiber.Ctx) error {
	username := r.username(c)

	err := subidGenerate(r.adminClient, username)
	if err != nil {
		if ierr, ok := err.(*ipa.IpaError); !ok || ierr.Code != 4002 {
			slog.Error("Failed to generate subordinate id range",
				"username", username,
				"err", err,
			)
			return c.Status(fiber.StatusInternalServerError).SendString(TC(c, "account.fatal_system_error"))
		}
	} else {
		slog.Info("AUDIT subordinate id range generated",
			"username", username,
			"ip", RemoteIP(c),
		)
	}

	vars := fiber.Map{}
	r.subidVars(username, vars)
	return c.Render("subid-card.html", vars)
}
