//go:build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Directory sync against the real FreeIPA, with the Google Directory API
// faked in this process. test/sync/mokey.toml points mokey at it through
// host.docker.internal; the service account key is generated here, copied
// into the container, and its token_uri is the fake too.

const (
	syncFakeAddr = "0.0.0.0:18867"
	syncFakeURL  = "http://host.docker.internal:18867"
	syncKeyPath  = "/tmp/google-sa.json"
	syncManaged  = "it-sync-managed"
	syncMapped   = "it-sync-devs"
	syncRuled    = "it-sync-research"
	// syncRuled is nested in syncParent, which is nested in syncGrand
	syncParent      = "it-sync-parent"
	syncGrand       = "it-sync-grand"
	syncHBAC        = "it-sync-grand-login"
	syncGoogleGroup = "devs@sync.test"
	syncToken       = "it-sync-access-token"
	syncPerm        = "Mokey Sync Group Membership"
	syncPriv        = "Mokey Directory Sync"
)

var mokeyCtr = envOr("MOKEY_IT_MOKEY_CONTAINER", "demo-mokey-1")

type fakeGoogleUser struct{ email, given, family, full, ou, dept string }

type fakeGoogle struct {
	mu      sync.Mutex
	users   []fakeGoogleUser
	members []string // emails in syncGoogleGroup
}

func (f *fakeGoogle) set(users []fakeGoogleUser, members ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users, f.members = users, members
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/token" {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("assertion") == "" {
			http.Error(w, "no assertion", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": syncToken, "token_type": "Bearer", "expires_in": 3600})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+syncToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/admin/directory/v1/users":
		var users []map[string]any
		for _, u := range f.users {
			gu := map[string]any{
				"primaryEmail": u.email,
				"name":         map[string]string{"givenName": u.given, "familyName": u.family, "fullName": u.full},
				"orgUnitPath":  u.ou,
			}
			if u.dept != "" {
				gu["organizations"] = []map[string]any{{"department": u.dept, "primary": true}}
			}
			users = append(users, gu)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"users": users})
	case "/admin/directory/v1/groups/" + syncGoogleGroup + "/members":
		var m []map[string]string
		for _, e := range f.members {
			m = append(m, map[string]string{"email": e, "type": "USER"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"members": m})
	default:
		http.NotFound(w, r)
	}
}

func syncStand(t *testing.T) *fakeGoogle {
	t.Helper()
	stand(t)
	if os.Getenv("MOKEY_IT_SYNC") == "" {
		t.Skip("MOKEY_IT_SYNC is not set")
	}
	// docs/guides/directory-sync.md: members of the sync's groups only.
	// Kept between runs, like the stand's other permissions; so are the groups.
	for _, args := range [][]string{
		{"group-add", syncManaged, "--desc=mokey sync tests: managed"},
		{"group-add", syncMapped, "--desc=mokey sync tests: mapped"},
		{"group-add", syncRuled, "--desc=mokey sync tests: rule target"},
		{"group-add", syncParent, "--desc=mokey sync tests: parent of the rule target"},
		{"group-add", syncGrand, "--desc=mokey sync tests: grandparent of the rule target"},
		{"group-add-member", syncParent, "--groups=" + syncRuled},
		{"group-add-member", syncGrand, "--groups=" + syncParent},
		{"hbacrule-add", syncHBAC},
		{"hbacrule-add-user", syncHBAC, "--groups=" + syncGrand},
		{"permission-add", syncPerm, "--type=group", "--right=write", "--attrs=member",
			"--filter=" + syncFilter},
		// a stand from before the rule group got the old filter
		{"permission-mod", syncPerm, "--filter=" + syncFilter},
		{"privilege-add", syncPriv, "--desc=Directory sync group membership"},
		{"privilege-add-permission", syncPriv, "--permissions=" + syncPerm},
		{"role-add-privilege", "Mokey User Manager", "--privileges=" + syncPriv},
	} {
		if out, err := ipaCmd("", args...); err != nil && !strings.Contains(out, "already") && !strings.Contains(out, "no modifications") {
			t.Fatalf("ipa %v: %s: %s", args, err, out)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "it-sync@sync-test.iam.gserviceaccount.com",
		"private_key_id": "it", "token_uri": syncFakeURL + "/token",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	})
	f := filepath.Join(t.TempDir(), "google-sa.json")
	// readable by mokey's user after docker cp; a throwaway key for the fake
	if err := os.WriteFile(f, b, 0o644); err != nil { // #nosec G306
		t.Fatal(err)
	}
	if out, err := runDocker("", "cp", f, mokeyCtr+":"+syncKeyPath); err != nil {
		t.Fatalf("docker cp key: %s: %s", err, out)
	}

	fake := &fakeGoogle{}
	ln, err := net.Listen("tcp", syncFakeAddr)
	if err != nil {
		t.Fatalf("fake Directory API: %s", err)
	}
	srv := &http.Server{Handler: fake, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return fake
}

const syncFilter = "(|(cn=" + syncManaged + ")(cn=" + syncMapped + ")(cn=" + syncRuled + "))"

// syncApply posts the admin Apply with the locks, deletes and users losing
// groups the admin expects, then waits for the background run to end
func syncApply(t *testing.T, admin *client, disable, groups int) {
	t.Helper()
	if body := syncApplyWait(t, admin, disable, groups); !strings.Contains(body, "mokey-pill is-ok") {
		t.Fatalf("sync run not OK: %s", body)
	}
}

// syncApplyWait returns the status fragment after the run
func syncApplyWait(t *testing.T, admin *client, disable, groups int) string {
	t.Helper()
	code, body := admin.hx("/admin/sync/apply", url.Values{"disable": {strconv.Itoa(disable)}, "delete": {"0"}, "groups": {strconv.Itoa(groups)}})
	if code != http.StatusOK || strings.Contains(body, "alert-danger") || strings.Contains(body, "alert-warning") {
		t.Fatalf("apply: %d %s", code, body)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, body = admin.do("GET", "/admin/sync/status", nil, true)
		if !strings.Contains(body, "A run is applying changes") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("apply did not finish: %s", body)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return body
}

var (
	cnRe     = regexp.MustCompile(`(?m)^\s*cn: (.+)$`)
	lockedRe = regexp.MustCompile(`(?mi)^\s*nsaccountlock: TRUE$`)
)

func locked(t *testing.T, uid string) bool { return lockedRe.MatchString(userRaw(t, uid)) }

func cn(t *testing.T, uid string) string {
	t.Helper()
	if m := cnRe.FindStringSubmatch(userRaw(t, uid)); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func groupHas(t *testing.T, group, uid string) bool {
	t.Helper()
	out := mustIPA(t, "group-show", group, "--raw")
	return regexp.MustCompile(`(?m)^\s*member: uid=` + regexp.QuoteMeta(uid) + `,`).MatchString(out)
}

// Three Google users, two in the mapped group: created with no password, in
// the managed and mapped groups, cn from Google. Then one leaves (locked),
// one is renamed and leaves the Google group (cn follows, mapped group
// removed) and one an admin blocks (stays locked though still in Google);
// the leaver's return unlocks it, which only the sync's own lock marker
// allows.
func TestSyncGoogleToFreeIPA(t *testing.T) {
	fake := syncStand(t)
	var uids []string
	var users []fakeGoogleUser
	for _, s := range []string{"a", "b", "c"} {
		uid := "s" + runID + s
		uids = append(uids, uid)
		cleanupUser(t, uid)
		users = append(users, fakeGoogleUser{email: uid + "@sync.test", given: "Sync", family: strings.ToUpper(s), full: "Sync Person " + strings.ToUpper(s)})
	}
	a, b, c := uids[0], uids[1], uids[2]
	fake.set(users, users[0].email, users[1].email)

	admin := login(t, "admin", ipaAdminPw)
	syncApply(t, admin, 0, 0)
	for i, uid := range uids {
		if out := mustIPA(t, "user-show", uid, "--all"); !regexp.MustCompile(`(?m)^\s*Password: False$`).MatchString(out) {
			t.Errorf("%s: want no password:\n%s", uid, out)
		}
		if got := cn(t, uid); got != users[i].full {
			t.Errorf("%s: cn = %q, want %q", uid, got, users[i].full)
		}
		if !groupHas(t, syncManaged, uid) {
			t.Errorf("%s not in %s", uid, syncManaged)
		}
		if locked(t, uid) {
			t.Errorf("%s created locked", uid)
		}
	}
	if !groupHas(t, syncMapped, a) || !groupHas(t, syncMapped, b) || groupHas(t, syncMapped, c) {
		t.Errorf("%s members: want %s and %s only", syncMapped, a, b)
	}

	mustIPA(t, "user-disable", c)
	users[0].full = "Sync Renamed A"
	fake.set([]fakeGoogleUser{users[0], users[2]})
	// a loses the mapped group
	syncApply(t, admin, 1, 1)
	if !locked(t, b) {
		t.Errorf("%s left Google but is not locked", b)
	}
	if !locked(t, c) {
		t.Errorf("admin-blocked %s was unlocked", c)
	}
	if got := cn(t, a); got != "Sync Renamed A" {
		t.Errorf("%s: cn after rename = %q", a, got)
	}
	if groupHas(t, syncMapped, a) {
		t.Errorf("%s still in %s after leaving the Google group", a, syncMapped)
	}
	if _, body := admin.do("GET", "/admin/sync/status?tab=decisions", nil, true); !strings.Contains(body, c) {
		t.Errorf("Decisions do not list the blocked %s:\n%s", c, body)
	}

	fake.set(users, users[0].email, users[1].email)
	syncApply(t, admin, 0, 0)
	if locked(t, b) {
		t.Errorf("%s came back to Google but stays locked", b)
	}
	if !groupHas(t, syncMapped, a) {
		t.Errorf("%s not back in %s", a, syncMapped)
	}
	if !locked(t, c) {
		t.Errorf("admin-blocked %s was unlocked", c)
	}
}

// A mapped group left out of the permission filter, on the real FreeIPA's
// effective rights: the run fails with one error and a Decisions row, and
// the group is not touched.
func TestSyncStaleFilter(t *testing.T) {
	fake := syncStand(t)
	uid := "s" + runID + "f"
	cleanupUser(t, uid)
	u := fakeGoogleUser{email: uid + "@sync.test", given: "Sync", family: "F", full: "Sync Person F"}
	fake.set([]fakeGoogleUser{u}, u.email)

	mustIPA(t, "permission-mod", syncPerm, "--filter=(cn="+syncManaged+")")
	t.Cleanup(func() { _, _ = ipaCmd("", "permission-mod", syncPerm, "--filter="+syncFilter) })

	admin := login(t, "admin", ipaAdminPw)
	if body := syncApplyWait(t, admin, 0, 0); !strings.Contains(body, "mokey-pill is-danger") {
		t.Fatalf("want a failed run: %s", body)
	}
	if !groupHas(t, syncManaged, uid) {
		t.Errorf("%s not created in %s", uid, syncManaged)
	}
	if groupHas(t, syncMapped, uid) {
		t.Errorf("%s added to %s outside the filter", uid, syncMapped)
	}
	_, body := admin.do("GET", "/admin/sync/status?tab=decisions", nil, true)
	if !strings.Contains(body, "change members of "+syncMapped) {
		t.Errorf("Decisions do not list %s:\n%s", syncMapped, body)
	}
}

// Attribute rules on the real FreeIPA (test/sync/mokey.toml): a user in a
// sub-OU of /Research and one in department Engineering join the rule
// group, one in neither does not; moving out of the OU removes the group.
// Settings shows the HBAC rule that reaches the rule group two nesting
// levels up, through FreeIPA's memberofindirect_group.
func TestSyncRules(t *testing.T) {
	fake := syncStand(t)
	var users []fakeGoogleUser
	var uids []string
	for _, s := range []struct{ id, ou, dept string }{{"r", "/Research/Lab", ""}, {"e", "/Sales", "Engineering"}, {"o", "/Sales", "Sales"}} {
		uid := "s" + runID + s.id
		uids = append(uids, uid)
		cleanupUser(t, uid)
		users = append(users, fakeGoogleUser{email: uid + "@sync.test", given: "Sync", family: strings.ToUpper(s.id), full: "Sync Rule " + strings.ToUpper(s.id), ou: s.ou, dept: s.dept})
	}
	r, e, o := uids[0], uids[1], uids[2]
	fake.set(users)

	admin := login(t, "admin", ipaAdminPw)
	syncApply(t, admin, 0, 0)
	if !groupHas(t, syncRuled, r) || !groupHas(t, syncRuled, e) || groupHas(t, syncRuled, o) {
		t.Errorf("%s members: want %s (OU) and %s (department) only", syncRuled, r, e)
	}

	_, body := admin.do("GET", "/admin/sync/status?tab=settings", nil, true)
	for _, want := range []string{"it-research", "org_unit: /research", "it-eng", "department: engineering", syncHBAC + " · via " + syncGrand} {
		if !strings.Contains(body, want) {
			t.Errorf("Settings tab: no %q:\n%s", want, body)
		}
	}

	users[0].ou = "/Sales"
	fake.set(users)
	syncApply(t, admin, 0, 1)
	if groupHas(t, syncRuled, r) {
		t.Errorf("%s left /Research but is still in %s", r, syncRuled)
	}
	if !groupHas(t, syncRuled, e) {
		t.Errorf("%s lost %s though department Engineering still matches", e, syncRuled)
	}
}
