package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/api/option"
)

type fakeDirectory struct {
	pages   map[string]map[string]any // by pageToken
	members map[string][]map[string]string
	failTok string // pageToken that returns 500
}

func (f fakeDirectory) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.ToLower(r.URL.Path)
		switch {
		case strings.HasSuffix(p, "/users"):
			tok := r.URL.Query().Get("pageToken")
			if tok != "" && tok == f.failTok {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(f.pages[tok])
		case strings.HasSuffix(p, "/members"):
			if r.URL.Query().Get("includeDerivedMembership") != "true" {
				t.Error("nested membership not requested")
			}
			for g, m := range f.members {
				if strings.HasSuffix(p, "/groups/"+g+"/members") {
					_ = json.NewEncoder(w).Encode(map[string]any{"members": m})
					return
				}
			}
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fakeKeyFile(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "svc@proj.iam.gserviceaccount.com",
		"private_key_id": "k1", "token_uri": "http://127.0.0.1:1/token",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	})
	f := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func testGoogleSource(t *testing.T, f fakeDirectory, cfg googleSourceConfig, groups []string) *googleSource {
	t.Helper()
	srv := f.start(t)
	cfg.CredentialsFile = fakeKeyFile(t)
	cfg.AdminEmail = "admin@example.com"
	src, err := newGoogleSource(context.Background(), cfg, groups,
		option.WithEndpoint(srv.URL+"/"), option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestGoogleSourceUsers(t *testing.T) {
	f := fakeDirectory{
		pages: map[string]map[string]any{
			"": {"nextPageToken": "p2", "users": []map[string]any{
				{"primaryEmail": "John@Example.com", "orgUnitPath": "/Eng", "name": map[string]string{"givenName": "John", "familyName": "Doe", "fullName": "John Doe"}},
				{"primaryEmail": "sus@example.com", "orgUnitPath": "/Eng", "suspended": true},
				{"primaryEmail": "arch@example.com", "orgUnitPath": "/Eng", "archived": true},
			}},
			"p2": {"users": []map[string]any{
				{"primaryEmail": "noname@example.com", "orgUnitPath": "/Eng/Platform"},
				{"primaryEmail": "sales@example.com", "orgUnitPath": "/Sales"},
				{"primaryEmail": "x@other.org", "orgUnitPath": "/Eng"},
			}},
		},
		members: map[string][]map[string]string{"devops@example.com": {
			{"email": "JOHN@example.com", "type": "USER"},
			{"email": "nested@example.com", "type": "GROUP"},
		}},
	}
	src := testGoogleSource(t, f, googleSourceConfig{Customer: "my_customer", OrgUnits: []string{"/eng"}, Domains: []string{"example.com"}},
		[]string{"devops@example.com"})

	users, err := src.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var emails []string
	for _, u := range users {
		emails = append(emails, u.Email)
	}
	if !slices.Equal(emails, []string{"john@example.com", "noname@example.com"}) {
		t.Fatalf("emails = %v", emails)
	}
	if !slices.Equal(users[0].Groups, []string{"devops@example.com"}) || users[0].GivenName != "John" || users[0].FullName != "John Doe" {
		t.Errorf("john = %+v", users[0])
	}
}

func TestGoogleSourcePageErrorFails(t *testing.T) {
	f := fakeDirectory{
		pages:   map[string]map[string]any{"": {"nextPageToken": "p2", "users": []map[string]any{{"primaryEmail": "a@example.com"}}}},
		failTok: "p2",
	}
	src := testGoogleSource(t, f, googleSourceConfig{Customer: "my_customer"}, nil)
	users, err := src.Users(context.Background())
	if err == nil || users != nil {
		t.Fatalf("users = %v, err = %v; want error and no users", users, err)
	}
}

func TestGoogleSourceLowercase(t *testing.T) {
	f := fakeDirectory{
		pages:   map[string]map[string]any{"": {"users": []map[string]any{{"primaryEmail": "Mixed.Case@Example.com"}}}},
		members: map[string][]map[string]string{"devops@example.com": {{"email": "MIXED.case@EXAMPLE.com", "type": "USER"}}},
	}
	src := testGoogleSource(t, f, googleSourceConfig{Customer: "c"}, []string{"DevOps@Example.com"})
	users, err := src.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Email != "mixed.case@example.com" || !slices.Equal(users[0].Groups, []string{"devops@example.com"}) {
		t.Fatalf("users = %+v", users)
	}
}
