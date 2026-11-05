// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

// Read-only JSON API for automation. Routes are registered before the CSRF
// middleware, so they never load or create a session.

const (
	apiDefaultLimit = 100
	apiMaxLimit     = auditRingSize
)

func apiError(c fiber.Ctx, code int, msg string) error {
	return c.Status(code).JSON(fiber.Map{"error": msg})
}

func (r *Router) RequireAPIToken(c fiber.Ctx) error {
	token, ok := strings.CutPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	if ok && token != "" {
		// hash both sides so the comparison is constant time in length too
		got := sha256.Sum256([]byte(token))
		for _, t := range viper.GetStringSlice("api.tokens") {
			want := sha256.Sum256([]byte(t))
			if t != "" && subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
				return c.Next()
			}
		}
	}

	slog.Warn("API request with missing or invalid token",
		"path", c.Path(),
		"ip", RemoteIP(c),
	)
	c.Set(fiber.HeaderWWWAuthenticate, "Bearer")
	return apiError(c, fiber.StatusUnauthorized, "unauthorized")
}

func (r *Router) APIEvents(c fiber.Ctx) error {
	after, err := strconv.ParseInt(c.Query("after", "0"), 10, 64)
	if err != nil || after < 0 {
		return apiError(c, fiber.StatusBadRequest, "after must be a non-negative integer")
	}
	limit, err := strconv.Atoi(c.Query("limit", strconv.Itoa(apiDefaultLimit)))
	if err != nil || limit < 1 || limit > apiMaxLimit {
		return apiError(c, fiber.StatusBadRequest, "limit must be between 1 and "+strconv.Itoa(apiMaxLimit))
	}

	events := auditAfter(r.storage, after, limit)
	next := after
	if len(events) > 0 {
		next = events[len(events)-1].Seq
	}
	return c.JSON(fiber.Map{"events": events, "next": next})
}

type apiGroupRequest struct {
	Group       string    `json:"group"`
	Username    string    `json:"username"`
	Type        string    `json:"type"`
	RequestedAt time.Time `json:"requested_at"`
}

// APIGroupRequests lists pending join/leave requests of every managed
// group, leaving out requests already fulfilled as the /groups page does.
func (r *Router) APIGroupRequests(c fiber.Ctx) error {
	groups, err := groupFindManaged(r.adminClient)
	if err != nil {
		slog.Error("Failed to list managed groups for API", "err", err)
		return apiError(c, fiber.StatusBadGateway, "failed to list groups")
	}

	out := []apiGroupRequest{}
	for _, g := range groups {
		for _, req := range r.loadGroupRequests(g.Name) {
			member := false
			for _, m := range g.Members {
				if m == req.Username {
					member = true
					break
				}
			}
			if member == (req.Type == groupRequestJoin) {
				continue
			}
			out = append(out, apiGroupRequest{Group: g.Name, Username: req.Username, Type: req.Type, RequestedAt: req.RequestedAt})
		}
	}
	return c.JSON(fiber.Map{"requests": out})
}

func (r *Router) APIOTPRecovery(c fiber.Ctx) error {
	reqs := r.loadOTPRecoveryRequests()
	if reqs == nil {
		reqs = []OTPRecoveryRequest{}
	}
	return c.JSON(fiber.Map{"requests": reqs})
}
