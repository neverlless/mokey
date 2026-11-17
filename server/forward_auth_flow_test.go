package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/neverlless/goipa/ipatest"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	faMokeyHost = "id.example.test"
	faAppHost   = "kubecost.example.test"
	faWikiHost  = "wiki.example.test"
)

// newFAApp: Kubecost needs scientists (chemists is nested in it), walter is
// a chemist, hank is in no group; the test peer is a trusted proxy
func newFAApp(t *testing.T, configure func()) (*fiber.App, *Router, *ipatest.Server) {
	t.Helper()
	app, router, fake := newTestAppWith(t, func() {
		viper.Set("forward_auth.enabled", true)
		viper.Set("forward_auth.url", "https://"+faMokeyHost)
		viper.Set("server.trusted_proxies", []string{"0.0.0.0"})
		viper.Set("forward_auth.apps", []any{
			map[string]any{"host": faAppHost, "name": "Kubecost", "groups": []string{"scientists"}},
			map[string]any{"host": faWikiHost, "name": "Wiki"},
		})
		if configure != nil {
			configure()
		}
	})
	fake.AddGroup("chemists", ipatest.Group{})
	fake.AddGroup("scientists", ipatest.Group{MemberGroups: []string{"chemists"}})
	fake.AddUser("walter", ipatest.User{Password: "Secret123!", Email: "walter@example.test", First: "Walter", Last: "White"})
	fake.AddUser("hank", ipatest.User{Password: "Secret123!"})
	_, err := fake.ClientAs("admin").GroupAddMember("chemists", []string{"walter"}, nil)
	require.NoError(t, err)
	return app, router, fake
}

func (tc *testClient) send(method, target string, hdr map[string]string) *http.Response {
	tc.t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return tc.do(req)
}

var traefik = map[string]string{
	"X-Forwarded-Proto": "https",
	"X-Forwarded-Host":  faAppHost,
	"X-Forwarded-Uri":   "/dash?x=1",
	"Accept":            "text/html,application/xhtml+xml",
}

func (tc *testClient) verify(hdr map[string]string) *http.Response {
	tc.t.Helper()
	return tc.send("GET", "https://"+faMokeyHost+faVerifyPath, hdr)
}

func with(base map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

// faStart follows verify → /.mokey/start and returns the continue URL
func faStart(t *testing.T, tc *testClient) string {
	t.Helper()
	resp := tc.verify(traefik)
	require.Equal(t, fiber.StatusFound, resp.StatusCode)
	resp = tc.send("GET", resp.Header.Get("Location"), nil)
	require.Equal(t, fiber.StatusFound, resp.StatusCode)
	return resp.Header.Get("Location")
}

// faToCallback runs start and continue (hop included) for a signed-in user
// and returns the callback URL
func faToCallback(t *testing.T, tc *testClient) string {
	t.Helper()
	cont := faStart(t, tc)
	resp := tc.send("GET", cont, nil)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	resp = tc.send("GET", cont+"&hop=1", nil)
	require.Equal(t, fiber.StatusFound, resp.StatusCode, readBody(t, resp))
	return resp.Header.Get("Location")
}

// faSignIn signs walter in to mokey and Kubecost
func faSignIn(t *testing.T, tc *testClient) {
	t.Helper()
	tc.login("walter", "Secret123!")
	resp := tc.send("GET", faToCallback(t, tc), nil)
	require.Equal(t, fiber.StatusFound, resp.StatusCode, readBody(t, resp))
	require.NotEmpty(t, tc.cookies[faSessionCookie])
}

func TestFAVerifyWithoutSession(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newFAApp(t, nil)
	tc := newTestClient(t, app)

	resp := tc.verify(traefik)
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("no-store", resp.Header.Get("Cache-Control"))
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal("https", loc.Scheme)
	assert.Equal(faAppHost, loc.Host)
	assert.Equal("/.mokey/start", loc.Path)
	assert.Equal("https://"+faAppHost+"/dash?x=1", loc.Query().Get("rd"))

	resp = tc.verify(map[string]string{"X-Original-URL": "https://" + faAppHost + "/dash", "Accept": "text/html"})
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
	assert.Empty(resp.Header.Get("Location"))

	resp = tc.verify(with(traefik, "Accept", "application/json"))
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
	resp = tc.verify(with(traefik, "X-Requested-With", "XMLHttpRequest"))
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)
	resp = tc.verify(with(traefik, "Sec-Fetch-Mode", "cors"))
	assert.Equal(fiber.StatusUnauthorized, resp.StatusCode)

	resp = tc.verify(with(traefik, "X-Forwarded-Host", "evil.example.test"))
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
	assert.Empty(resp.Header.Get("Location"))
	assert.Equal("no-store", resp.Header.Get("Cache-Control"))
}

func TestFAVerifyUntrustedPeerUsesHost(t *testing.T) {
	app, _, _ := newFAApp(t, func() { viper.Set("server.trusted_proxies", []string{}) })
	tc := newTestClient(t, app)
	// forwarded headers from an untrusted peer are ignored: the Host is mokey's
	resp := tc.verify(traefik)
	assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
	resp = tc.send("GET", "https://"+faAppHost+faVerifyPath+"/dash", map[string]string{"Accept": "text/html"})
	assert.Equal(t, fiber.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "https://"+faAppHost+"/.mokey/start?rd=")
}

func TestFAFullFlow(t *testing.T) {
	assert := assert.New(t)
	app, router, _ := newFAApp(t, nil)
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")

	resp := tc.send("GET", "https://"+faAppHost+"/.mokey/start?rd="+url.QueryEscape("https://"+faAppHost+"/dash?x=1"), nil)
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	nonce := cookieNamed(resp, faNonceCookie)
	require.NotNil(t, nonce)
	assertHostCookie(t, nonce)
	cont := resp.Header.Get("Location")
	assert.True(strings.HasPrefix(cont, "https://"+faMokeyHost+faContinuePath+"?p="), cont)

	// the cross-site arrival carries no Strict cookie: answer with a hop
	// page and leave the mokey session alone
	resp = tc.send("GET", cont, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Empty(resp.Header.Values("Set-Cookie"))
	body := readBody(t, resp)
	assert.Contains(body, `http-equiv="refresh"`)
	assert.Contains(body, "hop=1")
	assert.Contains(body, fmt.Sprintf(T("forward_auth.hop_continuing"), "Kubecost"))
	assert.Contains(body, `href="/static/css/style.css`)
	assert.Regexp(`<script nonce="[^"]+">`, body)

	resp = tc.send("GET", cont+"&hop=1", nil)
	require.Equal(t, fiber.StatusFound, resp.StatusCode)
	cb, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(faAppHost, cb.Host)
	assert.Equal("/.mokey/callback", cb.Path)
	assert.NotEmpty(cb.Query().Get("code"))

	resp = tc.send("GET", cb.String(), nil)
	require.Equal(t, fiber.StatusFound, resp.StatusCode)
	assert.Equal("https://"+faAppHost+"/dash?x=1", resp.Header.Get("Location"))
	sc := cookieNamed(resp, faSessionCookie)
	require.NotNil(t, sc)
	assertHostCookie(t, sc)
	if cleared := cookieNamed(resp, faNonceCookie); assert.NotNil(cleared) {
		assert.Empty(cleared.Value)
		assert.True(cleared.Secure)
	}
	assert.True(auditHas(router, "forward-auth sign-in"))
	assert.False(router.lastSignIn("walter").IsZero())

	resp = tc.verify(traefik)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Equal("no-store", resp.Header.Get("Cache-Control"))
	assert.Equal("walter", resp.Header.Get("X-Auth-Request-User"))
	assert.Equal("walter", resp.Header.Get("X-Auth-Request-Preferred-Username"))
	assert.Equal("walter", resp.Header.Get("Remote-User"))
	assert.Equal("walter@example.test", resp.Header.Get("X-Auth-Request-Email"))
	assert.Equal("walter@example.test", resp.Header.Get("Remote-Email"))
	assert.Equal("Walter White", resp.Header.Get("Remote-Name"))
	groups := strings.Split(resp.Header.Get("X-Auth-Request-Groups"), ",")
	assert.Contains(groups, "chemists")
	assert.Contains(groups, "scientists")
	assert.Equal(resp.Header.Get("X-Auth-Request-Groups"), resp.Header.Get("Remote-Groups"))

	// the app session is per host
	resp = tc.verify(with(traefik, "X-Forwarded-Host", faWikiHost))
	assert.Equal(fiber.StatusFound, resp.StatusCode)
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func assertHostCookie(t *testing.T, c *http.Cookie) {
	t.Helper()
	assert.True(t, c.Secure, c.Name)
	assert.True(t, c.HttpOnly, c.Name)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite, c.Name)
	assert.Equal(t, "/", c.Path, c.Name)
	assert.Empty(t, c.Domain, c.Name)
}

func TestFASignInAsksForLoginOnce(t *testing.T) {
	assert := assert.New(t)
	app, _, _ := newFAApp(t, nil)
	tc := newTestClient(t, app)

	cont := faStart(t, tc)
	tc.send("GET", cont, nil)
	resp := tc.send("GET", cont+"&hop=1", nil)
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Equal("/auth/login", resp.Header.Get("Location"))

	tc.getCSRF("/auth/login")
	resp = tc.postForm("/auth/authenticate", url.Values{"username": {"walter"}, "password": {"Secret123!"}}, nil)
	assert.Equal(fiber.StatusNoContent, resp.StatusCode)
	next := resp.Header.Get("HX-Redirect")
	assert.True(strings.HasPrefix(next, faContinuePath+"?p="), next)
	assert.Contains(next, "hop=1")

	resp = tc.send("GET", "https://"+faMokeyHost+next, nil)
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	assert.Contains(resp.Header.Get("Location"), "https://"+faAppHost+"/.mokey/callback?code=")
}

func TestFACallbackRejects(t *testing.T) {
	app, router, _ := newFAApp(t, nil)

	t.Run("replayed code", func(t *testing.T) {
		tc := newTestClient(t, app)
		tc.login("walter", "Secret123!")
		cb := faToCallback(t, tc)
		nonce := tc.cookies[faNonceCookie]
		require.Equal(t, fiber.StatusFound, tc.send("GET", cb, nil).StatusCode)
		delete(tc.cookies, faSessionCookie)
		tc.cookies[faNonceCookie] = nonce
		resp := tc.send("GET", cb, nil)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		assert.Nil(t, cookieNamed(resp, faSessionCookie))
	})
	t.Run("other host", func(t *testing.T) {
		tc := newTestClient(t, app)
		tc.login("walter", "Secret123!")
		cb := faToCallback(t, tc)
		resp := tc.send("GET", strings.Replace(cb, faAppHost, faWikiHost, 1), nil)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		assert.Nil(t, cookieNamed(resp, faSessionCookie))
		// and the code is spent
		resp = tc.send("GET", cb, nil)
		assert.Nil(t, cookieNamed(resp, faSessionCookie))
	})
	t.Run("missing nonce", func(t *testing.T) {
		tc := newTestClient(t, app)
		tc.login("walter", "Secret123!")
		cb := faToCallback(t, tc)
		delete(tc.cookies, faNonceCookie)
		resp := tc.send("GET", cb, nil)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
		assert.Nil(t, cookieNamed(resp, faSessionCookie))
	})
	t.Run("different nonce", func(t *testing.T) {
		tc := newTestClient(t, app)
		tc.login("walter", "Secret123!")
		cb := faToCallback(t, tc)
		tc.cookies[faNonceCookie] = "not-the-nonce"
		resp := tc.send("GET", cb, nil)
		assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
		assert.Nil(t, cookieNamed(resp, faSessionCookie))
	})
	t.Run("wrong state", func(t *testing.T) {
		tc := newTestClient(t, app)
		tc.login("walter", "Secret123!")
		cb := faToCallback(t, tc)
		resp := tc.send("GET", cb+"x", nil)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		assert.Nil(t, cookieNamed(resp, faSessionCookie))
		if c := cookieNamed(resp, faNonceCookie); assert.NotNil(t, c, "nonce cleared on failure") {
			assert.Empty(t, c.Value)
		}
		body := readBody(t, resp)
		assert.Contains(t, body, `href="https://`+faMokeyHost+`/static/css/style.css`)
	})
	t.Run("password changed after continue", func(t *testing.T) {
		tc := newTestClient(t, app)
		tc.login("walter", "Secret123!")
		cb := faToCallback(t, tc)
		// the marker is in seconds; a later one invalidates this session
		later := strconv.FormatInt(time.Now().Add(5*time.Second).Unix(), 10)
		require.NoError(t, router.storage.Set(PasswordChangedPrefix+"walter", []byte(later), time.Minute))
		defer func() { _ = router.storage.Delete(PasswordChangedPrefix + "walter") }()
		resp := tc.send("GET", cb, nil)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		assert.Nil(t, cookieNamed(resp, faSessionCookie))
	})
	t.Run("mokey session gone", func(t *testing.T) {
		tc := newTestClient(t, app)
		tc.login("walter", "Secret123!")
		cb := faToCallback(t, tc)
		tc.getCSRF("/")
		tc.postForm("/auth/logout", nil, htmx)
		resp := tc.send("GET", cb, nil)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
		assert.Nil(t, cookieNamed(resp, faSessionCookie))
	})
}

func TestFAStartRejects(t *testing.T) {
	app, _, _ := newFAApp(t, nil)
	tc := newTestClient(t, app)
	for _, rd := range []string{
		"https://kubecost.example.test@evil.org/",
		"//evil.org",
		`https:/\evil.org`,
		"https://KUBECOST.example.test.evil.org/",
		"http://" + faAppHost + "/",
		"https://" + faWikiHost + "/",
	} {
		resp := tc.send("GET", "https://"+faAppHost+"/.mokey/start?rd="+url.QueryEscape(rd), nil)
		assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode, rd)
		assert.Empty(t, resp.Header.Get("Location"), rd)
	}
	for _, p := range []string{"/.mokey/start", "/.mokey/callback", "/.mokey/signout"} {
		resp := tc.send("GET", "https://evil.example.test"+p+"?rd="+url.QueryEscape("https://evil.example.test/"), nil)
		assert.Equal(t, fiber.StatusNotFound, resp.StatusCode, p)
	}
}

func TestFAExpiredPending(t *testing.T) {
	app, _, _ := newFAApp(t, nil)
	tc := newTestClient(t, app)
	tc.login("walter", "Secret123!")
	resp := tc.send("GET", "https://"+faMokeyHost+faContinuePath+"?p=gone&hop=1", nil)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), T("forward_auth.expired_title"))
}

func TestFADeniedAtContinue(t *testing.T) {
	assert := assert.New(t)
	app, router, _ := newFAApp(t, nil)
	tc := newTestClient(t, app)
	tc.login("hank", "Secret123!")
	cont := faStart(t, tc)
	resp := tc.send("GET", cont+"&hop=1", nil)
	assert.Equal(fiber.StatusForbidden, resp.StatusCode)
	body := readBody(t, resp)
	assert.Contains(body, "Kubecost")
	assert.Contains(body, "scientists")
	assert.True(auditHas(router, "forward-auth denied"))
	assert.Nil(cookieNamed(resp, faSessionCookie))
}

func TestFARecheckRevokes(t *testing.T) {
	cases := map[string]func(t *testing.T, r *Router, fake *ipatest.Server){
		"left group": func(t *testing.T, _ *Router, fake *ipatest.Server) {
			_, err := fake.ClientAs("admin").GroupRemoveMember("chemists", []string{"walter"}, nil)
			require.NoError(t, err)
		},
		"disabled": func(t *testing.T, _ *Router, fake *ipatest.Server) {
			require.NoError(t, fake.ClientAs("admin").UserDisable("walter"))
		},
		"time-bound membership expired": func(t *testing.T, r *Router, fake *ipatest.Server) {
			allowServiceAccountRemovals(t)
			fake.GrantPrivilege(keytabUser, "Modify Group membership")
			now := time.Now()
			require.NoError(t, r.putTimedMember(TimedMembership{
				Group: "chemists", Username: "walter", Until: now.Add(-time.Minute), GrantedBy: "skyler", GrantedAt: now.Add(-time.Hour),
			}))
			r.membershipExpirySweep(now, false)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			app, router, fake := newFAApp(t, func() { viper.Set("forward_auth.recheck", "1ns") })
			tc := newTestClient(t, app)
			faSignIn(t, tc)
			require.Equal(t, fiber.StatusOK, tc.verify(traefik).StatusCode)

			change(t, router, fake)
			resp := tc.verify(traefik)
			assert.Equal(t, fiber.StatusForbidden, resp.StatusCode)
			assertAppHostPage(t, resp)
			s, err := router.faLoadSession(tc.cookies[faSessionCookie])
			require.NoError(t, err)
			assert.Nil(t, s)
			assert.Equal(t, fiber.StatusFound, tc.verify(traefik).StatusCode)
		})
	}
}

func TestFARecheckRecordsSignIn(t *testing.T) {
	app, router, _ := newFAApp(t, func() { viper.Set("forward_auth.recheck", "1ns") })
	tc := newTestClient(t, app)
	faSignIn(t, tc)
	require.NoError(t, router.storage.Delete(lastSeenPrefix+"walter"))
	require.Equal(t, fiber.StatusOK, tc.verify(traefik).StatusCode)
	assert.False(t, router.lastSignIn("walter").IsZero())
}

func TestFAMokeySignOutEndsAppSession(t *testing.T) {
	app, _, _ := newFAApp(t, nil)
	tc := newTestClient(t, app)
	faSignIn(t, tc)
	require.Equal(t, fiber.StatusOK, tc.verify(traefik).StatusCode)

	tc.getCSRF("/")
	tc.postForm("/auth/logout", nil, htmx)
	assert.Equal(t, fiber.StatusFound, tc.verify(traefik).StatusCode)
	assert.Equal(t, fiber.StatusUnauthorized, tc.verify(with(traefik, "Accept", "application/json")).StatusCode)
}

func TestFAAppSignOut(t *testing.T) {
	assert := assert.New(t)
	app, router, _ := newFAApp(t, nil)
	tc := newTestClient(t, app)
	faSignIn(t, tc)
	id := tc.cookies[faSessionCookie]

	resp := tc.send("GET", "https://"+faAppHost+"/.mokey/signout", nil)
	assert.Equal(fiber.StatusFound, resp.StatusCode)
	if c := cookieNamed(resp, faSessionCookie); assert.NotNil(c) {
		assert.Empty(c.Value)
		assertHostCookie(t, c)
	}
	s, err := router.faLoadSession(id)
	require.NoError(t, err)
	assert.Nil(s)
	assert.Equal(fiber.StatusFound, tc.verify(traefik).StatusCode)

	page := resp.Header.Get("Location")
	assert.True(strings.HasPrefix(page, "https://"+faMokeyHost+"/forward-auth/signedout?"), page)
	resp = tc.send("GET", page, nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	assert.Empty(resp.Header.Values("Set-Cookie"))
	resp = tc.send("GET", page+"&hop=1", nil)
	assert.Equal(fiber.StatusOK, resp.StatusCode)
	body := readBody(t, resp)
	assert.Contains(body, "Kubecost")
	assert.Contains(body, `hx-post="/auth/logout"`)
	assert.Regexp(csrfPattern, body)

	// a GET never signs anyone out of mokey
	assert.Equal(fiber.StatusOK, tc.get("/account").StatusCode)
}

func TestFAVerifyNotRateLimited(t *testing.T) {
	app, _, _ := newFAApp(t, func() { viper.Set("server.rate_limit_max", 5) })
	tc := newTestClient(t, app)
	for i := 0; i < 50; i++ {
		resp := tc.send("POST", "https://"+faMokeyHost+faVerifyPath, map[string]string{"X-Original-URL": "https://" + faAppHost + "/"})
		require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode, i)
	}
	// failed callbacks still count
	var last int
	for i := 0; i < 6; i++ {
		last = tc.send("GET", "https://"+faAppHost+"/.mokey/callback?code=x&state=y", nil).StatusCode
	}
	assert.Equal(t, fiber.StatusTooManyRequests, last)
}

func TestFADisabledHasNoRoutes(t *testing.T) {
	app, _, _ := newTestApp(t)
	tc := newTestClient(t, app)
	for _, p := range []string{faVerifyPath, faContinuePath + "?p=x", "/.mokey/start", "/.mokey/callback", "/.mokey/signout", "/forward-auth/signedout"} {
		assert.Equal(t, fiber.StatusNotFound, tc.send("GET", "https://"+faAppHost+p, nil).StatusCode, p)
	}
}

// a page shown on the app's host loads mokey's assets from forward_auth.url
func assertAppHostPage(t *testing.T, resp *http.Response) {
	t.Helper()
	origin := "https://" + faMokeyHost
	body := readBody(t, resp)
	assert.Contains(t, body, `href="`+origin+`/static/css/style.css`)
	assert.NotContains(t, body, `href="/static/`)
	csp := resp.Header.Get("Content-Security-Policy")
	assert.Contains(t, csp, "style-src 'self' 'unsafe-inline' "+origin)
	assert.Contains(t, csp, "font-src 'self' "+origin)
	assert.Contains(t, csp, "default-src 'self';")
}

func TestFAMokeyPagesKeepCSP(t *testing.T) {
	app, _, _ := newFAApp(t, nil)
	tc := newTestClient(t, app)
	resp := tc.get("/auth/login")
	csp := resp.Header.Get("Content-Security-Policy")
	assert.NotContains(t, csp, faMokeyHost)
	assert.NotContains(t, csp, "font-src")
	assert.Contains(t, readBody(t, resp), `href="/static/css/style.css`)

	resp = tc.get("/static/css/style.css")
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
}
