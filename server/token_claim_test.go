package server

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v3"
	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userAddGate holds every user_add until two have arrived or release is
// called, so two submits that both get past the token check both reach
// FreeIPA
type userAddGate struct {
	next    http.RoundTripper
	arrived atomic.Int32
	open    chan struct{}
	once    sync.Once
}

func (g *userAddGate) release() { g.once.Do(func() { close(g.open) }) }

func (g *userAddGate) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		if bytes.Contains(body, []byte(`"user_add"`)) {
			if g.arrived.Add(1) == 2 {
				g.release()
			}
			<-g.open
		}
	}
	return g.next.RoundTrip(req)
}

func gateUserAdd(t *testing.T, router *Router, fake *ipatest.Server) *userAddGate {
	t.Helper()
	hc := fake.HTTPClient()
	next := hc.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	gate := &userAddGate{next: next, open: make(chan struct{})}
	c, err := ipa.New(ipa.WithHost(fake.Host()), ipa.WithRealm(fake.Realm()), ipa.WithHTTPClient(&http.Client{Transport: gate, Jar: hc.Jar}))
	require.NoError(t, err)
	router.adminClient = c
	return gate
}

func inviteForm(username string) url.Values {
	return url.Values{
		"username": {username}, "first": {"Kim"}, "last": {"Wexler"},
		"password": {"NewSecret456!"}, "password2": {"NewSecret456!"},
	}
}

func TestInviteAcceptConcurrentSubmitOnce(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, false)
	allowServiceAccountAdds(t)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists"})
	gate := gateUserAdd(t, router, fake)

	names := []string{"kim", "kwexler"}
	guests := make([]*testClient, len(names))
	for i := range names {
		guests[i] = newTestClient(t, tc.app)
		guests[i].getCSRF("/auth/invite/" + token)
	}

	codes := make([]int, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() {
			// a request that never reaches user_add frees the other one
			defer gate.release()
			resp := guests[i].postForm("/auth/invite/"+token, inviteForm(name), nil)
			_ = resp.Body.Close()
			codes[i] = resp.StatusCode
		})
	}
	wg.Wait()

	created := 0
	for _, name := range names {
		if fakeUser(fake, name) != nil {
			created++
		}
	}
	assert.Equal(t, 1, created, "accounts created from one invite link")
	assert.Len(t, groupMembers(t, fake, "chemists"), 1)
	assert.ElementsMatch(t, []int{fiber.StatusOK, fiber.StatusNotFound}, codes)
}

func TestInviteAcceptFailedAttemptKeepsLink(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, false)
	allowServiceAccountAdds(t)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists"})

	guest := newTestClient(t, tc.app)
	guest.getCSRF("/auth/invite/" + token)
	bad := inviteForm("kim")
	bad.Del("last")
	resp := guest.postForm("/auth/invite/"+token, bad, nil)
	_ = resp.Body.Close()
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	assert.Nil(t, fakeUser(fake, "kim"))

	resp = guest.postForm("/auth/invite/"+token, inviteForm("kim"), nil)
	_ = resp.Body.Close()
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	assert.NotNil(t, fakeUser(fake, "kim"))
	assert.Contains(t, groupMembers(t, fake, "chemists"), "kim")

	resp = guest.postForm("/auth/invite/"+token, inviteForm("kwexler"), nil)
	_ = resp.Body.Close()
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
	assert.Nil(t, fakeUser(fake, "kwexler"))
}

func TestInviteAcceptClaimStorageDownRefused(t *testing.T) {
	tc, router, fake, _ := inviteGroupsApp(t, true, false)
	token := groupInviteToken(t, router, InviteGroup{Name: "chemists"})
	router.storage = &usedMarkerDown{router.storage}

	resp, _ := acceptPresetInvite(t, tc.app, token, "kim")
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
	assert.Nil(t, fakeUser(fake, "kim"))
	assert.NotContains(t, groupMembers(t, fake, "chemists"), "kim")
}
