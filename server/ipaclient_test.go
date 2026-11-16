package server

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	ipa "github.com/neverlless/goipa"
	"github.com/neverlless/goipa/ipatest"
)

// sharedTestHTTPClient is newIPAHTTPClient trusting fake's CA, with a dial counter.
func sharedTestHTTPClient(t *testing.T, fake *ipatest.Server) (*http.Client, *atomic.Int32) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(fake.CACert()) {
		t.Fatal("fake CA not parsed")
	}
	hc := newIPAHTTPClient(pool)
	tr := hc.Transport.(*http.Transport)
	var dials atomic.Int32
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return dial(ctx, network, addr)
	}
	return hc, &dials
}

func TestIPAHTTPClientReusesConnections(t *testing.T) {
	fake := ipatest.NewServer(t)
	fake.AddUser("alice", ipatest.User{})
	fake.AddUser("bob", ipatest.User{})
	hc, dials := sharedTestHTTPClient(t, fake)

	// A new goipa client per request, as isLoggedIn does
	for i := range 10 {
		uid := []string{"alice", "bob"}[i%2]
		c, err := ipa.New(ipa.WithHost(fake.Host()), ipa.WithRealm(fake.Realm()), ipa.WithHTTPClient(hc))
		if err != nil {
			t.Fatal(err)
		}
		c.SetSessionID(fake.Session(uid))
		if _, err := c.UserShow(uid); err != nil {
			t.Fatal(err)
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("10 sequential requests dialed %d connections, want 1", n)
	}
}

// The shared http.Client carries no cookie jar: goipa sends ipa_session as a
// header from each Client, so one user's session never rides on another's request.
func TestIPAHTTPClientKeepsSessionsApart(t *testing.T) {
	fake := ipatest.NewServer(t)
	users := []string{"alice", "bob", "carol"}
	for _, u := range users {
		fake.AddUser(u, ipatest.User{})
	}
	hc, _ := sharedTestHTTPClient(t, fake)
	if hc.Jar != nil {
		t.Fatal("shared FreeIPA http.Client must not have a cookie jar")
	}
	sids := map[string]string{}
	for _, u := range users {
		sids[u] = fake.Session(u)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 300)
	for i := range 300 {
		uid := users[i%len(users)]
		wg.Go(func() {
			c, err := ipa.New(ipa.WithHost(fake.Host()), ipa.WithRealm(fake.Realm()), ipa.WithHTTPClient(hc))
			if err != nil {
				errs <- err
				return
			}
			c.SetSessionID(sids[uid])
			id, err := c.WhoAmI()
			if err != nil {
				errs <- err
				return
			}
			if id.Object != "user" || id.Arguments[0] != uid {
				t.Errorf("session of %s answered as %+v", uid, id)
			}
			if c.SessionID() != sids[uid] {
				t.Errorf("session of %s changed to another session id", uid)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestSharedIPAHTTPClientIsBuiltOnce(t *testing.T) {
	first, second := sharedIPAHTTPClient(), sharedIPAHTTPClient()
	if first != second {
		t.Fatal("each call built a new FreeIPA http.Client")
	}
}
