package server

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	ipa "github.com/neverlless/goipa"
	"github.com/spf13/viper"
)

const (
	masterResultTTL   = 5 * time.Minute
	masterFailureTTL  = time.Minute
	masterReadTimeout = 15 * time.Second
)

// masterClients keeps one logged-in client per other FreeIPA master: each
// keytab login starts a gokrb5 renewal goroutine, so clients are never
// built per request
type masterClients struct {
	mu    sync.Mutex
	hosts map[string]*masterClient
}

type masterClient struct {
	mu       sync.Mutex
	client   *ipa.Client
	loggedIn bool
	logins   map[string]time.Time
	err      error
	readAt   time.Time
}

func (m *masterClients) get(host string) *masterClient {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hosts == nil {
		m.hosts = map[string]*masterClient{}
	}
	mc, ok := m.hosts[host]
	if !ok {
		mc = &masterClient{}
		m.hosts[host] = mc
	}
	return mc
}

// masterLastAuth returns krbLastSuccessfulAuth of every user as one master
// recorded it: FreeIPA does not replicate it. Results are cached; without
// fetch only a fresh cached result is returned (nil, nil otherwise).
func (r *Router) masterLastAuth(host string, fetch bool) (map[string]time.Time, error) {
	mc := r.masters.get(host)
	mc.mu.Lock()
	defer mc.mu.Unlock()
	ttl := masterResultTTL
	if mc.err != nil {
		ttl = masterFailureTTL
	}
	if !mc.readAt.IsZero() && time.Since(mc.readAt) < ttl {
		return mc.logins, mc.err
	}
	if !fetch {
		return nil, nil
	}
	mc.logins, mc.err = mc.read(host)
	mc.readAt = time.Now()
	if mc.err != nil {
		slog.Warn("Failed to read logins from a FreeIPA master", "host", host, "err", mc.err)
	}
	return mc.logins, mc.err
}

func (mc *masterClient) read(host string) (map[string]time.Time, error) {
	if mc.client == nil {
		client, err := newIPAClientForHost(host)
		if err != nil {
			return nil, err
		}
		client.StickySession(false)
		mc.client = client
	}
	if !mc.loggedIn {
		// bounded by gokrb5's own KDC timeouts; the KDC comes from
		// krb5.conf, not from this master
		if err := ipaKeytabLogin(mc.client, viper.GetString("site.keytab"), viper.GetString("site.ktuser")); err != nil {
			return nil, err
		}
		mc.loggedIn = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), masterReadTimeout)
	defer cancel()
	entries, err := ipa.FindEntries(ctx, mc.client, "user_find", nil, ipa.Options{"all": true, "no_members": true}, helpdeskSizeLimit)
	if err != nil && !errors.Is(err, ipa.ErrTruncated) {
		// log in again next time; goipa destroys the replaced Kerberos client
		mc.loggedIn = false
		return nil, err
	}
	logins := map[string]time.Time{}
	for _, e := range entries {
		if last := e.Time("krblastsuccessfulauth"); !last.IsZero() {
			logins[e.Str("uid")] = last
		}
	}
	return logins, nil
}

// otherMastersLastAuth merges the logins recorded by every master except
// the one mokey talks to, keeping the latest per user
func (r *Router) otherMastersLastAuth(client *ipa.Client, masters []string, fetch bool) (map[string]time.Time, []string) {
	self, _, _ := strings.Cut(client.Host(), ":")
	var (
		mu          sync.Mutex
		wg          sync.WaitGroup
		unreachable []string
	)
	merged := map[string]time.Time{}
	for _, host := range masters {
		if strings.EqualFold(host, self) {
			continue
		}
		wg.Go(func() {
			logins, err := r.masterLastAuth(host, fetch)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				unreachable = append(unreachable, host)
				return
			}
			for uid, t := range logins {
				if t.After(merged[uid]) {
					merged[uid] = t
				}
			}
		})
	}
	wg.Wait()
	slices.Sort(unreachable)
	return merged, unreachable
}
