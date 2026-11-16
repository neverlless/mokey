package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// spDir adds the attributes ipatest does not keep (manager,
// krbprincipalexpiration) on top of a shadow fake that renders the rest.
type spDir struct {
	mu      sync.Mutex
	manager map[string]string
	expires map[string]time.Time
	refuse  bool
	mods    int
	fake    *ipatest.Server
	shadow  *ipatest.Server
}

const spSecret = "test-secret-placeholder"

func newSponsorApp(t *testing.T, cfg *lifecycleConfig) (*testClient, *Router, *spDir, *bytes.Buffer) {
	t.Helper()
	app, router, fake := newTestApp(t)
	router.lifecycle = cfg
	d := &spDir{manager: map[string]string{}, expires: map[string]time.Time{}, fake: fake, shadow: ipatest.NewServer(t)}

	extend := func(e map[string]any) {
		uid := fmt.Sprint(e["uid"].([]any)[0])
		if m := d.manager[uid]; m != "" {
			e["manager"] = []string{m}
		}
		if at := d.expires[uid]; !at.IsZero() {
			e["krbprincipalexpiration"] = []any{map[string]string{"__datetime__": at.UTC().Format(ipa.IpaDatetimeFormat)}}
		}
	}
	shadowRPC := func(c ipatest.Call) (json.RawMessage, *ipa.IpaError) {
		opts := ipa.Options{}
		for k, v := range c.Options {
			if k != "manager" && k != "version" {
				opts[k] = v
			}
		}
		res, err := d.shadow.ClientAs("admin").RPC(c.Method, c.Args, opts)
		if err != nil {
			if ierr, ok := err.(*ipa.IpaError); ok {
				return nil, ierr
			}
			return nil, &ipa.IpaError{Code: 4301, Message: err.Error()}
		}
		return res.Result.Data, nil
	}
	fake.Handle("user_show", func(c ipatest.Call) (any, *ipa.IpaError) {
		raw, ierr := shadowRPC(c)
		if ierr != nil {
			return nil, ierr
		}
		var e map[string]any
		require.NoError(t, json.Unmarshal(raw, &e))
		d.mu.Lock()
		defer d.mu.Unlock()
		extend(e)
		return map[string]any{"result": e}, nil
	})
	fake.Handle("user_find", func(c ipatest.Call) (any, *ipa.IpaError) {
		raw, ierr := shadowRPC(c)
		if ierr != nil {
			return nil, ierr
		}
		var all []map[string]any
		require.NoError(t, json.Unmarshal(raw, &all))
		d.mu.Lock()
		defer d.mu.Unlock()
		out := []map[string]any{}
		for _, e := range all {
			uid := fmt.Sprint(e["uid"].([]any)[0])
			if want, ok := c.Options["manager"]; ok && sponsorUID(d.manager[uid]) != fmt.Sprint(want) {
				continue
			}
			extend(e)
			out = append(out, e)
		}
		return map[string]any{"result": out, "count": len(out), "truncated": false}, nil
	})
	fake.Handle("user_mod", func(c ipatest.Call) (any, *ipa.IpaError) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.refuse {
			return nil, &ipa.IpaError{Code: 2100, Message: "Insufficient access: Insufficient 'write' privilege to the 'krbPrincipalExpiration' attribute"}
		}
		d.mods++
		v, _ := c.Options["krbprincipalexpiration"].(map[string]any)
		d.expires[c.Args[0]], _ = time.Parse(ipa.IpaDatetimeFormat, fmt.Sprint(v["__datetime__"]))
		return map[string]any{"result": map[string]any{}}, nil
	})

	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(NewAuditHandler(slog.NewTextHandler(&logs, nil), router.storage)))
	t.Cleanup(func() { slog.SetDefault(saved) })
	return newTestClient(t, app), router, d, &logs
}

// add creates uid; manager is stored as given (plain uid or DN).
func (d *spDir) add(uid string, u ipatest.User, manager string, expires time.Time) {
	u.Password = spSecret
	d.fake.AddUser(uid, u)
	d.shadow.AddUser(uid, u)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.manager[uid] = manager
	d.expires[uid] = expires
}

func (d *spDir) expiry(uid string) time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expires[uid]
}

func (d *spDir) modCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mods
}

func renewalCfg() *lifecycleConfig {
	return &lifecycleConfig{Renewal: 365 * 24 * time.Hour, Reminders: []int{30}, MaxChanges: 50}
}

func TestSponsoredSectionListsExactlyMine(t *testing.T) {
	assert := assert.New(t)
	tc, router, d, _ := newSponsorApp(t, renewalCfg())
	now := time.Now()
	d.add("walter", ipatest.User{First: "Walter", Last: "White"}, "", time.Time{})
	d.add("jesse", ipatest.User{First: "Jesse", Last: "Pinkman"}, walterDN, now.Add(10*24*time.Hour))
	d.add("skinny", ipatest.User{First: "Skinny", Last: "Pete"}, "walter", now.Add(200*24*time.Hour))
	d.add("jane", ipatest.User{First: "Jane", Last: "Margolis"}, "walter", now.Add(-24*time.Hour))
	d.add("badger", ipatest.User{First: "Brandon", Last: "Mayhew"}, "skyler", time.Time{})
	router.recordSignIn("skinny", now.Add(-48*time.Hour))

	tc.login("walter", spSecret)
	body := readBody(t, tc.get("/groups"))
	assert.Contains(body, T("groups.sponsored"))
	for _, uid := range []string{"jesse", "skinny", "jane"} {
		assert.Contains(body, `"username": "`+uid+`"`)
	}
	assert.NotContains(body, "badger")
	assert.Contains(body, "mokey-pill is-warn")
	assert.Contains(body, "mokey-pill is-danger")
	assert.Contains(body, strings.TrimSuffix(T("groups.sponsored_last_active"), "%s"))
}

func TestSponsoredSectionHidden(t *testing.T) {
	t.Run("not a sponsor", func(t *testing.T) {
		tc, _, d, _ := newSponsorApp(t, renewalCfg())
		d.add("walter", ipatest.User{}, "", time.Time{})
		d.add("jesse", ipatest.User{}, "skyler", time.Time{})
		tc.login("walter", spSecret)
		assert.NotContains(t, readBody(t, tc.get("/groups")), T("groups.sponsored"))
	})
	t.Run("renewal off", func(t *testing.T) {
		tc, _, d, _ := newSponsorApp(t, &lifecycleConfig{Reminders: []int{30}, MaxChanges: 50})
		d.add("walter", ipatest.User{}, "", time.Time{})
		d.add("jesse", ipatest.User{}, "walter", time.Now().Add(time.Hour))
		tc.login("walter", spSecret)
		assert.NotContains(t, readBody(t, tc.get("/groups")), T("groups.sponsored"))
	})
	t.Run("lifecycle off", func(t *testing.T) {
		tc, _, d, _ := newSponsorApp(t, nil)
		d.add("walter", ipatest.User{}, "", time.Time{})
		d.add("jesse", ipatest.User{}, "walter", time.Now().Add(time.Hour))
		tc.login("walter", spSecret)
		assert.NotContains(t, readBody(t, tc.get("/groups")), T("groups.sponsored"))
		resp := tc.postForm("/groups/sponsored/extend", url.Values{"username": {"jesse"}}, htmx)
		assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
		assert.Equal(t, 0, d.modCount())
	})
}

func TestSponsoredExtendCappedByOwnExpiry(t *testing.T) {
	assert := assert.New(t)
	tc, router, d, _ := newSponsorApp(t, renewalCfg())
	sink := newFakeSMTP(t)
	now := time.Now()
	own := now.Add(100 * 24 * time.Hour).Truncate(time.Second)
	d.add("walter", ipatest.User{}, "", own)
	d.add("jesse", ipatest.User{Email: "jesse@example.test"}, walterDN, now.Add(24*time.Hour))

	tc.login("walter", spSecret)
	resp := tc.postForm("/groups/sponsored/extend", url.Values{"username": {"jesse"}}, htmx)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Contains(readBody(t, resp), `id="groups-pane"`)
	assert.True(own.Equal(d.expiry("jesse")), "got %s", d.expiry("jesse"))

	ext := auditEvents(router, "lifecycle expiry extended")
	if assert.Len(ext, 1) {
		assert.Equal("walter", ext[0].Attrs["by"])
		assert.Equal("jesse", ext[0].Attrs["username"])
	}
	if assert.Equal(1, sink.count()) {
		assert.Contains(sink.all()[0], T("email_template.account_extended_subject"))
	}
}

func TestSponsoredExtendWithoutOwnExpiry(t *testing.T) {
	tc, _, d, _ := newSponsorApp(t, renewalCfg())
	now := time.Now()
	d.add("walter", ipatest.User{}, "", time.Time{})
	// already expired accounts can be extended
	d.add("jane", ipatest.User{}, "walter", now.Add(-24*time.Hour))

	tc.login("walter", spSecret)
	resp := tc.postForm("/groups/sponsored/extend", url.Values{"username": {"jane"}}, htmx)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.WithinDuration(t, now.Add(365*24*time.Hour), d.expiry("jane"), time.Minute)
}

// Review Focus 1
func TestSponsoredExtendSomeoneElses(t *testing.T) {
	tc, router, d, _ := newSponsorApp(t, renewalCfg())
	now := time.Now()
	d.add("walter", ipatest.User{}, "", time.Time{})
	d.add("badger", ipatest.User{}, "uid=skyler,cn=users,cn=accounts,dc=test,dc=local", now.Add(24*time.Hour))
	d.add("pete", ipatest.User{}, "", now.Add(24*time.Hour))

	tc.login("walter", spSecret)
	for _, uid := range []string{"badger", "pete", "nobody"} {
		resp := tc.postForm("/groups/sponsored/extend", url.Values{"username": {uid}}, htmx)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode, uid)
	}
	assert.Equal(t, 0, d.modCount())
	assert.Empty(t, auditEvents(router, "lifecycle expiry extended"))
}

// Review Focus 2
func TestSponsoredExtendSponsorExpired(t *testing.T) {
	assert := assert.New(t)
	tc, router, d, _ := newSponsorApp(t, renewalCfg())
	now := time.Now()
	d.add("walter", ipatest.User{}, "", now.Add(-time.Hour))
	d.add("jesse", ipatest.User{}, "walter", now.Add(24*time.Hour))

	tc.login("walter", spSecret)
	body := readBody(t, tc.get("/groups"))
	assert.Contains(body, html.EscapeString(T("groups.sponsored_you_expired")))
	assert.Contains(body, "disabled")

	resp := tc.postForm("/groups/sponsored/extend", url.Values{"username": {"jesse"}}, htmx)
	assert.Equal(fiber.StatusBadRequest, resp.StatusCode)
	assert.Equal(0, d.modCount())
	assert.Empty(auditEvents(router, "lifecycle expiry extended"))
}

func TestSponsoredExtendNotLater(t *testing.T) {
	tc, _, d, _ := newSponsorApp(t, renewalCfg())
	now := time.Now()
	own := now.Add(30 * 24 * time.Hour)
	d.add("walter", ipatest.User{}, "", own)
	d.add("jesse", ipatest.User{}, "walter", own)
	d.add("skinny", ipatest.User{}, "walter", time.Time{})

	tc.login("walter", spSecret)
	body := readBody(t, tc.get("/groups"))
	assert.Contains(t, body, T("groups.sponsored_at_cap"))
	assert.Contains(t, body, T("groups.sponsored_no_end"))
	for _, uid := range []string{"jesse", "skinny"} {
		resp := tc.postForm("/groups/sponsored/extend", url.Values{"username": {uid}}, htmx)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode, uid)
	}
	assert.Equal(t, 0, d.modCount())
}

func TestSponsoredExtendRefusedByFreeIPA(t *testing.T) {
	tc, router, d, logs := newSponsorApp(t, renewalCfg())
	d.add("walter", ipatest.User{}, "", time.Time{})
	d.add("jesse", ipatest.User{}, "walter", time.Now().Add(24*time.Hour))
	d.refuse = true

	tc.login("walter", spSecret)
	resp := tc.postForm("/groups/sponsored/extend", url.Values{"username": {"jesse"}}, htmx)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, T("groups.sponsored_extend_failed"), readBody(t, resp))
	assert.Contains(t, logs.String(), "Mokey Modify Principal Expiration")
	assert.Empty(t, auditEvents(router, "lifecycle expiry extended"))
}
