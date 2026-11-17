package server

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

type syncSource interface {
	Users(ctx context.Context) ([]syncSourceUser, error)
}

var googleScopes = []string{admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupMemberReadonlyScope}

type googleSource struct {
	svc    *admin.Service
	cfg    googleSourceConfig
	groups []string
}

func googleTokenSource(ctx context.Context, cfg googleSourceConfig) (oauth2.TokenSource, error) {
	if cfg.CredentialsFile != "" {
		b, err := os.ReadFile(cfg.CredentialsFile)
		if err != nil {
			return nil, err
		}
		creds, err := google.CredentialsFromJSONWithTypeAndParams(ctx, b, google.ServiceAccount,
			google.CredentialsParams{Scopes: googleScopes, Subject: cfg.AdminEmail})
		if err != nil {
			return nil, fmt.Errorf("service account key %s: %w", cfg.CredentialsFile, err)
		}
		return creds.TokenSource, nil
	}
	return impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: cfg.ServiceAccountEmail,
		Scopes:          googleScopes,
		Subject:         cfg.AdminEmail,
	})
}

// newGoogleSource builds a source. groups are the Google group emails whose
// members are resolved; opts are appended after the token source so tests can
// override the endpoint and HTTP client.
func newGoogleSource(ctx context.Context, cfg googleSourceConfig, groups []string, opts ...option.ClientOption) (*googleSource, error) {
	ts, err := googleTokenSource(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("google credentials: %w", err)
	}
	svc, err := admin.NewService(ctx, append([]option.ClientOption{option.WithTokenSource(ts)}, opts...)...)
	if err != nil {
		return nil, err
	}
	return &googleSource{svc: svc, cfg: cfg, groups: groups}, nil
}

func (s *googleSource) keep(u *admin.User) bool {
	if u.Suspended || u.Archived {
		return false
	}
	email := strings.ToLower(u.PrimaryEmail)
	if len(s.cfg.Domains) > 0 {
		_, domain, _ := strings.Cut(email, "@")
		if !slices.Contains(s.cfg.Domains, domain) {
			return false
		}
	}
	if len(s.cfg.OrgUnits) > 0 && !slices.ContainsFunc(s.cfg.OrgUnits, func(ou string) bool {
		path, ou := strings.ToLower(u.OrgUnitPath), strings.ToLower(ou)
		return path == ou || strings.HasPrefix(path, strings.TrimSuffix(ou, "/")+"/")
	}) {
		return false
	}
	return true
}

// Users returns active users with their mapped group memberships. Any API
// error fails the whole call: a partial list must never reach the planner.
func (s *googleSource) Users(ctx context.Context) ([]syncSourceUser, error) {
	memberOf := map[string][]string{}
	for _, g := range s.groups {
		err := s.svc.Members.List(g).IncludeDerivedMembership(true).MaxResults(200).Pages(ctx, func(m *admin.Members) error {
			for _, mem := range m.Members {
				if mem.Type == "USER" {
					e := strings.ToLower(mem.Email)
					memberOf[e] = append(memberOf[e], strings.ToLower(g))
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("list members of %s: %w", g, err)
		}
	}

	var out []syncSourceUser
	call := s.svc.Users.List().Customer(s.cfg.Customer).MaxResults(500).OrderBy("email")
	if s.cfg.Query != "" {
		call = call.Query(s.cfg.Query)
	}
	err := call.Pages(ctx, func(page *admin.Users) error {
		for _, u := range page.Users {
			if !s.keep(u) {
				continue
			}
			email := strings.ToLower(u.PrimaryEmail)
			su := syncSourceUser{Email: email, Groups: memberOf[email]}
			if u.Name != nil {
				su.GivenName, su.FamilyName, su.FullName = u.Name.GivenName, u.Name.FamilyName, u.Name.FullName
			}
			out = append(out, su)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return out, nil
}
