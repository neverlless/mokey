package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func apiGet(t *testing.T, app *fiber.App, path, bearer string) (*http.Response, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(readBody(t, resp)), &body))
	return resp, body
}

func newAPITestApp(t *testing.T) (*fiber.App, *Router, *ipatest.Server) {
	return newTestAppWith(t, func() {
		viper.Set("api.tokens", []string{"first-api-key", "second-api-key"})
	})
}

func TestAPIDisabledByDefault(t *testing.T) {
	app, _, _ := newTestApp(t)
	resp := newTestClient(t, app).get("/api/v1/events")
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
}

func TestAPIAuth(t *testing.T) {
	app, _, _ := newAPITestApp(t)

	for _, bearer := range []string{"", "wrong", "first-api-key-and-more"} {
		resp, body := apiGet(t, app, "/api/v1/events", bearer)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode, bearer)
		assert.Equal(t, "Bearer", resp.Header.Get("WWW-Authenticate"))
		assert.Equal(t, "unauthorized", body["error"])
		assert.Empty(t, resp.Header.Values("Set-Cookie"))
	}

	for _, bearer := range []string{"first-api-key", "second-api-key"} {
		resp, _ := apiGet(t, app, "/api/v1/events", bearer)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		assert.Equal(t, fiber.MIMEApplicationJSONCharsetUTF8, resp.Header.Get("Content-Type"))
		assert.Empty(t, resp.Header.Values("Set-Cookie"), "API calls must not open a session")
	}
}

func TestAPIEventsCursor(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newAPITestApp(t)

	_, body := apiGet(t, app, "/api/v1/events", "first-api-key")
	start := int64(body["next"].(float64))

	for _, u := range []string{"a", "b", "c"} {
		slog.Info("AUDIT User logged in", "username", u, "password", redactProbe)
	}

	after := func(seq int64) string { return "/api/v1/events?limit=2&after=" + strconv.FormatInt(seq, 10) }

	resp, body := apiGet(t, app, after(start), "first-api-key")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	events := body["events"].([]any)
	if assert.Len(events, 2) {
		first := events[0].(map[string]any)
		assert.Equal("a", first["username"])
		assert.Equal(float64(start+1), first["seq"])
		assert.Equal(redacted, first["attrs"].(map[string]any)["password"])
		assert.Equal("b", events[1].(map[string]any)["username"])
	}
	assert.Equal(float64(start+2), body["next"])

	_, body = apiGet(t, app, after(start+2), "first-api-key")
	events = body["events"].([]any)
	if assert.Len(events, 1) {
		assert.Equal("c", events[0].(map[string]any)["username"])
	}
	assert.Equal(float64(start+3), body["next"])

	// caught up: empty page, cursor stays
	_, body = apiGet(t, app, after(start+3), "first-api-key")
	assert.Empty(body["events"])
	assert.Equal(float64(start+3), body["next"])

	for _, q := range []string{"?after=-1", "?after=x", "?limit=0", "?limit=5000"} {
		resp, body := apiGet(t, app, "/api/v1/events"+q, "first-api-key")
		assert.Equal(fiber.StatusBadRequest, resp.StatusCode, q)
		assert.NotEmpty(body["error"])
	}
}

func TestAPIQueues(t *testing.T) {
	assert := assert.New(t)
	app, router, fake := newAPITestApp(t)
	fake.AddGroup("chemists", ipatest.Group{ManagerUsers: []string{"skyler"}, Members: []string{"walter"}})

	router.addGroupRequest("chemists", "jesse", groupRequestJoin, "7d")
	router.addGroupRequest("chemists", "walter", groupRequestLeave, "")
	// leaving a group they are not in: already fulfilled, not pending
	router.addGroupRequest("chemists", "walter2", groupRequestLeave, "")
	router.addOTPRecoveryRequest("hank")

	resp, body := apiGet(t, app, "/api/v1/group-requests", "first-api-key")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	reqs := body["requests"].([]any)
	if assert.Len(reqs, 2) {
		assert.Equal(map[string]any{"group": "chemists", "username": "jesse", "type": "join", "duration": "7d"}, without(reqs[0], "requested_at"))
		assert.Equal(map[string]any{"group": "chemists", "username": "walter", "type": "leave"}, without(reqs[1], "requested_at"))
	}

	resp, body = apiGet(t, app, "/api/v1/otp-recovery", "first-api-key")
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	reqs = body["requests"].([]any)
	if assert.Len(reqs, 1) {
		assert.Equal("hank", reqs[0].(map[string]any)["username"])
	}
}

func without(v any, key string) map[string]any {
	m := v.(map[string]any)
	delete(m, key)
	return m
}
