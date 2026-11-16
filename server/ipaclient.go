package server

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	ipa "github.com/neverlless/goipa"
)

// FreeIPA client factories. Package-level vars so tests can point them at a
// fake FreeIPA server; production always uses the goipa defaults.
var (
	newIPAClient            = func() (*ipa.Client, error) { return ipa.New(ipa.WithHTTPClient(sharedIPAHTTPClient())) }
	newIPAClientWithSession = func(sid string) (*ipa.Client, error) {
		c, err := ipa.New(ipa.WithHTTPClient(sharedIPAHTTPClient()))
		if err != nil {
			return nil, err
		}
		c.SetSessionID(sid)
		return c, nil
	}
	// newIPAClientForHost talks to one named FreeIPA master instead of the
	// one in /etc/ipa/default.conf
	newIPAClientForHost = func(host string) (*ipa.Client, error) {
		return ipa.New(ipa.WithHost(host), ipa.WithHTTPClient(sharedIPAHTTPClient()))
	}
	ipaKeytabLogin = func(c *ipa.Client, keytab, username string) error {
		return c.LoginWithKeytab(keytab, username)
	}
)

// sharedIPAHTTPClient keeps connections to FreeIPA open across requests:
// ipa.New without WithHTTPClient builds a new Transport per client, so every
// page paid a fresh TCP and TLS handshake. Sharing is safe because the client
// has no cookie jar; goipa sends each Client's ipa_session as a header.
var sharedIPAHTTPClient = sync.OnceValue(func() *http.Client {
	var pool *x509.CertPool
	if pem, err := os.ReadFile("/etc/ipa/ca.crt"); err == nil {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			pool = nil
		}
	}
	return newIPAHTTPClient(pool)
})

// newIPAHTTPClient mirrors goipa's own http.Client; a nil pool means the
// system roots, as in goipa.
func newIPAHTTPClient(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}
