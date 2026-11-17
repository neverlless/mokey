package server

import (
	"slices"
	"strings"
	"testing"
	"time"
)

var syncTestNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

const syncDay = 24 * time.Hour

func syncMarkerAgo(kind syncMarkerKind, d time.Duration) *syncMarker {
	return &syncMarker{Kind: kind, At: syncTestNow.Add(-d), By: "sync"}
}

func syncTestConfig(mut func(*syncConfig)) *syncConfig {
	c := &syncConfig{
		ManagedGroup:      "google2ipa-managed",
		Username:          "local_part",
		MaxUsernameLength: 32,
		Disable:           true,
		DeleteAfter:       30 * syncDay,
		Preserve:          true,
		DefaultGroups:     []string{"staff"},
		GroupMapping:      map[string][]string{"dev@example.com": {"developers"}, "ops@example.com": {"admins", "ops"}},
	}
	if mut != nil {
		mut(c)
	}
	return c
}

func syncU(uid string, groups ...string) syncUser {
	return syncUser{UID: uid, syncSourceUser: syncSourceUser{Email: uid + "@example.com", Groups: groups}}
}

func syncCheck(t *testing.T, name string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

func TestSyncResolve(t *testing.T) {
	in := []syncSourceUser{
		{Email: "John.Doe@Example.com"},
		{Email: "jane@example.com"},
		{Email: "jane@other.org"},      // collides with jane@example.com in local_part mode
		{Email: "bad+tag@example.com"}, // '+' is invalid in a uid
		{Email: "admin@example.com"},   // excluded
	}
	got, skipped, errs := syncResolve(in, "local_part", []string{"admin"}, 32)
	if len(got) != 1 || got[0].UID != "john.doe" {
		t.Fatalf("resolved = %+v", got)
	}
	syncCheck(t, "skipped", skipped, []string{"bad+tag", "jane"})
	if len(errs) != 2 {
		t.Errorf("errs = %v", errs)
	}

	got, skipped, _ = syncResolve(in, "email", []string{"admin.example.com"}, 32)
	uids := []string{}
	for _, u := range got {
		uids = append(uids, u.UID)
	}
	syncCheck(t, "email mode", uids, []string{"jane.example.com", "jane.other.org", "john.doe.example.com"})
	syncCheck(t, "email mode skipped", skipped, []string{"bad+tag.example.com"})
}

func TestSyncResolveTooLong(t *testing.T) {
	long := "a234567890123456789012345678901234@example.com" // 34-char local part
	got, skipped, errs := syncResolve([]syncSourceUser{{Email: long}, {Email: "ok@example.com"}}, "local_part", nil, 32)
	if len(got) != 1 || len(skipped) != 1 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "maxusername") {
		t.Fatalf("got=%v skipped=%v errs=%v", got, skipped, errs)
	}
}

func TestSyncResolveCase(t *testing.T) {
	in := []syncSourceUser{{Email: " Jo@Example.org ", Groups: []string{" Dev@Example.com", "ops@example.com"}}}
	got, skipped, errs := syncResolve(in, "local_part", nil, 32)
	if len(got) != 1 || got[0].UID != "jo" || len(skipped)+len(errs) != 0 {
		t.Fatalf("got=%+v skipped=%v errs=%v", got, skipped, errs)
	}
	if got[0].Email != "jo@example.org" {
		t.Errorf("Email = %q", got[0].Email)
	}
	syncCheck(t, "Groups", got[0].Groups, []string{"dev@example.com", "ops@example.com"})
	if in[0].Groups[0] != " Dev@Example.com" {
		t.Error("input groups must not be modified")
	}
	ipa := map[string]syncIPAUser{"jo": {UID: "jo", Email: "jo@example.org", Managed: true, Groups: []string{"staff", "developers", "admins", "ops"}}}
	p := syncBuild(got, nil, ipa, syncTestConfig(nil), syncTestNow)
	if len(p.AddGroups)+len(p.RemoveGroups)+len(p.Update) != 0 {
		t.Errorf("normalized user plans changes: %+v", p)
	}
	got, _, _ = syncResolve([]syncSourceUser{{Email: " Jo@Example.org "}}, "email", nil, 32)
	if len(got) != 1 || got[0].UID != "jo.example.org" {
		t.Fatalf("email mode: %+v", got)
	}
}

func TestSyncBuildLifecycle(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"active":   {UID: "active", Email: "active@example.com", Managed: true, Groups: []string{"staff"}},
		"gone":     {UID: "gone", Managed: true},
		"back":     {UID: "back", Email: "back@example.com", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, time.Hour), Groups: []string{"staff"}},
		"manual":   {UID: "manual", Email: "manual@example.com", Managed: true, Locked: true, Groups: []string{"staff"}}, // locked by admin
		"old":      {UID: "old", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, 31*syncDay)},
		"recent":   {UID: "recent", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, syncDay)},
		"legacy":   {UID: "legacy", Managed: false},
		"skipme":   {UID: "skipme", Managed: true},
		"excluded": {UID: "excluded", Managed: true},
	}
	users := []syncUser{syncU("active"), syncU("back"), syncU("legacy"), syncU("manual"), syncU("new")}
	p := syncBuild(users, []string{"skipme"}, ipa, syncTestConfig(func(c *syncConfig) { c.ExcludeUsers = []string{"excluded"} }), syncTestNow)

	if len(p.Create) != 1 || p.Create[0].UID != "new" {
		t.Errorf("Create = %+v", p.Create)
	}
	syncCheck(t, "Enable", p.Enable, []string{"back"})
	syncCheck(t, "BackInGoogle", p.BackInGoogle, []string{"manual"})
	syncCheck(t, "Disable", p.Disable, []string{"gone"})
	syncCheck(t, "Delete", p.Delete, []string{"old"})
	syncCheck(t, "Unmanaged", p.Unmanaged, []string{"legacy"})
	syncCheck(t, "Adopt", p.Adopt, nil)
	syncCheck(t, "AddGroups[new]", p.AddGroups["new"], []string{"staff"})
	if _, ok := p.AddGroups["legacy"]; ok {
		t.Error("unmanaged user must not get group changes")
	}
	if len(p.NewMarkers) != 0 || len(p.Update) != 0 {
		t.Errorf("NewMarkers=%v Update=%v", p.NewMarkers, p.Update)
	}
}

func TestSyncBuildAdopt(t *testing.T) {
	ipa := map[string]syncIPAUser{"legacy": {UID: "legacy", Email: "Legacy@Example.com", GivenName: "Old"}}
	p := syncBuild([]syncUser{syncU("legacy")}, nil, ipa, syncTestConfig(func(c *syncConfig) { c.AdoptExisting = true }), syncTestNow)
	syncCheck(t, "Adopt", p.Adopt, []string{"legacy"})
	syncCheck(t, "AddGroups", p.AddGroups["legacy"], []string{"staff"})
	if len(p.Update) != 0 {
		t.Errorf("adopted account is not updated in the run that adopts it: %+v", p.Update)
	}
}

func TestSyncBuildGroups(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"x": {UID: "x", Email: "x@example.com", Managed: true, Groups: []string{"staff", "admins", "ops", "manual-group"}},
	}
	p := syncBuild([]syncUser{syncU("x", "dev@example.com")}, nil, ipa, syncTestConfig(nil), syncTestNow)
	syncCheck(t, "add", p.AddGroups["x"], []string{"developers"})
	// only mapped groups are removed; staff (default) and manual-group are kept
	syncCheck(t, "remove", p.RemoveGroups["x"], []string{"admins", "ops"})
	if len(p.Update) != 0 {
		t.Errorf("Update = %+v", p.Update)
	}
}

func TestSyncBuildDisableOffAndNeverDelete(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"gone": {UID: "gone", Managed: true},
		"old":  {UID: "old", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, 365*syncDay)},
	}
	p := syncBuild(nil, nil, ipa, syncTestConfig(func(c *syncConfig) { c.Disable = false; c.DeleteAfter = 0 }), syncTestNow)
	if len(p.Disable)+len(p.Delete) != 0 {
		t.Errorf("got %+v", p)
	}
}

func TestSyncBuildDisableOffStillDeletesLocked(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"gone":   {UID: "gone", Managed: true},
		"old":    {UID: "old", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, 31*syncDay)},
		"nomark": {UID: "nomark", Managed: true, Locked: true},
	}
	p := syncBuild(nil, nil, ipa, syncTestConfig(func(c *syncConfig) { c.Disable = false }), syncTestNow)
	syncCheck(t, "Disable", p.Disable, nil)
	syncCheck(t, "Delete", p.Delete, []string{"old"})
	if m, ok := p.NewMarkers["nomark"]; !ok || m.Kind != syncMarkerFound {
		t.Errorf("NewMarkers = %v", p.NewMarkers)
	}
}

func TestSyncBuildBrake(t *testing.T) {
	ipa := map[string]syncIPAUser{}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		ipa[id] = syncIPAUser{UID: id, Email: id + "@example.com", Managed: true}
	}
	users := []syncUser{syncU("a"), syncU("b"), syncU("c"), syncU("d"), syncU("e"), syncU("f"), syncU("g"), syncU("h"), syncU("new")}
	ipa["old"] = syncIPAUser{UID: "old", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, 90*syncDay)}
	brake := syncTestConfig(func(c *syncConfig) { c.MaxDisablePercent = 20 })

	// 2 of 10 active = 20% -> allowed at 20
	p := syncBuild(users, nil, ipa, brake, syncTestNow)
	if p.Braked || len(p.Disable) != 2 || len(p.Delete) != 1 {
		t.Fatalf("20%%: %+v", p)
	}
	// 3 of 10 = 30% -> braked, delete suppressed too, creates still planned
	p = syncBuild(append(slices.Clone(users[:7]), syncU("new")), nil, ipa, brake, syncTestNow)
	if !p.Braked || p.Disable != nil || p.Delete != nil {
		t.Fatalf("30%%: %+v", p)
	}
	if len(p.Create) != 1 || p.Create[0].UID != "new" {
		t.Errorf("Create = %+v", p.Create)
	}
	if p.Empty() {
		t.Error("braked plan is not empty")
	}
	// a single disable never trips the brake
	small := map[string]syncIPAUser{"a": {UID: "a", Managed: true}, "b": {UID: "b", Managed: true}}
	p = syncBuild([]syncUser{syncU("a")}, nil, small, brake, syncTestNow)
	if p.Braked || len(p.Disable) != 1 {
		t.Fatalf("single: %+v", p)
	}
}

func TestSyncBuildAdminBlockNotEnabled(t *testing.T) {
	ipa := map[string]syncIPAUser{"blocked": {UID: "blocked", Email: "blocked@example.com", Managed: true, Locked: true}}
	p := syncBuild([]syncUser{syncU("blocked")}, nil, ipa, syncTestConfig(nil), syncTestNow)
	syncCheck(t, "Enable", p.Enable, nil)
	syncCheck(t, "BackInGoogle", p.BackInGoogle, []string{"blocked"})
	if len(p.NewMarkers) != 0 {
		t.Errorf("NewMarkers = %v", p.NewMarkers)
	}
}

func TestSyncBuildExpiredStaysLocked(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"exp":     {UID: "exp", Email: "exp@example.com", Managed: true, Locked: true, Expired: true, Groups: []string{"staff"}},
		"expopen": {UID: "expopen", Email: "expopen@example.com", Managed: true, Expired: true, Groups: []string{"staff"}},
	}
	p := syncBuild([]syncUser{syncU("exp"), syncU("expopen")}, nil, ipa, syncTestConfig(nil), syncTestNow)
	syncCheck(t, "Enable", p.Enable, nil)
	syncCheck(t, "Disable", p.Disable, nil)
	syncCheck(t, "Delete", p.Delete, nil)
	syncCheck(t, "BackInGoogle", p.BackInGoogle, []string{"exp"})
	if len(p.NewMarkers)+len(p.Update) != 0 || p.Changes() != 0 {
		t.Errorf("plan = %+v", p)
	}
}

func TestSyncBuildFoundMarkerNoDelete(t *testing.T) {
	ipa := map[string]syncIPAUser{"lost": {UID: "lost", Managed: true, Locked: true}}
	p := syncBuild(nil, nil, ipa, syncTestConfig(nil), syncTestNow)
	syncCheck(t, "Delete", p.Delete, nil)
	syncCheck(t, "Disable", p.Disable, nil)
	want := syncMarker{Kind: syncMarkerFound, At: syncTestNow, By: "sync"}
	if got, ok := p.NewMarkers["lost"]; !ok || got != want || len(p.NewMarkers) != 1 {
		t.Errorf("NewMarkers = %v", p.NewMarkers)
	}
	if p.Empty() {
		t.Error("plan with a marker to write is not empty")
	}
}

func TestSyncBuildDeleteAfterMarker(t *testing.T) {
	for _, kind := range []syncMarkerKind{syncMarkerSync, syncMarkerFound, syncMarkerLegacy} {
		ipa := map[string]syncIPAUser{
			"old":    {UID: "old", Managed: true, Locked: true, Marker: syncMarkerAgo(kind, 31*syncDay)},
			"edge":   {UID: "edge", Managed: true, Locked: true, Marker: syncMarkerAgo(kind, 30*syncDay)},
			"recent": {UID: "recent", Managed: true, Locked: true, Marker: syncMarkerAgo(kind, 29*syncDay)},
			"open":   {UID: "open", Managed: true, Marker: syncMarkerAgo(kind, 31*syncDay)}, // unlocked by hand
		}
		p := syncBuild([]syncUser{syncU("open")}, nil, ipa, syncTestConfig(nil), syncTestNow)
		syncCheck(t, string(kind)+" Delete", p.Delete, []string{"edge", "old"})
		if len(p.NewMarkers) != 0 {
			t.Errorf("%s NewMarkers = %v", kind, p.NewMarkers)
		}
	}
}

func TestSyncBuildFoundMarkerNoEnable(t *testing.T) {
	ipa := map[string]syncIPAUser{"f": {UID: "f", Email: "f@example.com", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerFound, syncDay)}}
	p := syncBuild([]syncUser{syncU("f")}, nil, ipa, syncTestConfig(nil), syncTestNow)
	syncCheck(t, "Enable", p.Enable, nil)
	syncCheck(t, "BackInGoogle", p.BackInGoogle, []string{"f"})
}

func TestSyncBuildLegacyEnable(t *testing.T) {
	ipa := map[string]syncIPAUser{"l": {UID: "l", Email: "l@example.com", Managed: true, Locked: true, Expired: true, Marker: syncMarkerAgo(syncMarkerLegacy, 90*syncDay)}}
	p := syncBuild([]syncUser{syncU("l")}, nil, ipa, syncTestConfig(nil), syncTestNow)
	syncCheck(t, "Enable", p.Enable, []string{"l"})
	syncCheck(t, "BackInGoogle", p.BackInGoogle, nil)
}

func TestSyncBuildStaleMarkerCleared(t *testing.T) {
	ipa := map[string]syncIPAUser{
		// marker left behind after an enable whose marker removal failed
		"half": {UID: "half", Email: "half@example.com", Managed: true, Marker: syncMarkerAgo(syncMarkerSync, time.Hour), Groups: []string{"staff"}},
		// unlocked by an admin after a found marker, then gone again: disabled, marker kept for the runner to rewrite
		"left":   {UID: "left", Managed: true, Marker: syncMarkerAgo(syncMarkerFound, syncDay)},
		"legacy": {UID: "legacy", Email: "legacy@example.com", Managed: true, Marker: syncMarkerAgo(syncMarkerLegacy, syncDay), Groups: []string{"staff"}},
		"locked": {UID: "locked", Email: "locked@example.com", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerFound, syncDay), Groups: []string{"staff"}},
	}
	p := syncBuild([]syncUser{syncU("half"), syncU("legacy"), syncU("locked")}, nil, ipa, syncTestConfig(nil), syncTestNow)
	// "locked" is back in Google: its old found marker must not make a later departure an instant delete
	syncCheck(t, "ClearMarkers", p.ClearMarkers, []string{"half", "legacy", "locked"})
	syncCheck(t, "BackInGoogle", p.BackInGoogle, []string{"locked"})
	syncCheck(t, "Enable", p.Enable, nil)
	syncCheck(t, "Disable", p.Disable, []string{"left"})
	if p.Empty() || p.Changes() != 1 {
		t.Errorf("Empty=%v Changes=%d", p.Empty(), p.Changes())
	}
	if !(syncPlan{}).Empty() || (syncPlan{ClearMarkers: []string{"x"}}).Empty() || (syncPlan{ClearMarkers: []string{"x"}}).Changes() != 0 {
		t.Error("ClearMarkers counts for Empty, not for Changes")
	}
}

func TestSyncBuildUpdateNames(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"n":     {UID: "n", Email: "n@example.com", GivenName: "Nat", FamilyName: "Old", FullName: "Nat Old", Managed: true},
		"same":  {UID: "same", Email: "same@example.com", GivenName: "S", FamilyName: "T", FullName: "S T", Managed: true},
		"blank": {UID: "blank", Email: "blank@example.com", GivenName: "B", FamilyName: "L", FullName: "B L", Managed: true},
	}
	n := syncU("n")
	n.GivenName, n.FamilyName, n.FullName = "Nat", "New", "Nat New"
	same := syncU("same")
	same.GivenName, same.FamilyName, same.FullName = "S", "T", "S T"
	blank := syncU("blank") // Google returned no names
	p := syncBuild([]syncUser{n, same, blank}, nil, ipa, syncTestConfig(nil), syncTestNow)
	if len(p.Update) != 1 {
		t.Fatalf("Update = %+v", p.Update)
	}
	want := syncUpdate{
		UID:  "n",
		From: syncSourceUser{Email: "n@example.com", GivenName: "Nat", FamilyName: "Old", FullName: "Nat Old"},
		To:   syncSourceUser{Email: "n@example.com", GivenName: "Nat", FamilyName: "New", FullName: "Nat New"},
	}
	got := p.Update[0]
	if got.UID != want.UID || got.From.Email != want.From.Email || got.From.FamilyName != want.From.FamilyName ||
		got.To.FamilyName != want.To.FamilyName || got.To.FullName != want.To.FullName || got.From.FullName != want.From.FullName ||
		got.To.GivenName != "Nat" || got.To.Groups != nil || got.From.Groups != nil {
		t.Errorf("Update = %+v, want %+v", got, want)
	}
}

func TestSyncBuildUpdateEmailManaged(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"john": {UID: "john", Managed: true, Email: "john@a.com", Groups: []string{"staff"}},
		"case": {UID: "case", Managed: true, Email: "Case@Example.com", Groups: []string{"staff"}},
		"none": {UID: "none", Managed: true, Groups: []string{"staff"}},
	}
	users := []syncUser{
		{UID: "john", syncSourceUser: syncSourceUser{Email: "john@b.com"}},
		syncU("case"),
		syncU("none"),
	}
	p := syncBuild(users, nil, ipa, syncTestConfig(nil), syncTestNow)
	if len(p.Conflicts) != 0 {
		t.Errorf("Conflicts = %v", p.Conflicts)
	}
	var uids []string
	for _, up := range p.Update {
		uids = append(uids, up.UID)
		if up.UID == "john" && (up.From.Email != "john@a.com" || up.To.Email != "john@b.com") {
			t.Errorf("john update = %+v", up)
		}
	}
	syncCheck(t, "Update", uids, []string{"john", "none"})
}

func TestSyncBuildLockedReusedUIDConflict(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"john": {UID: "john", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, time.Hour), Email: "john@a.com", GivenName: "John", Groups: []string{"staff", "admins"}},
		"same": {UID: "same", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, time.Hour), Email: "Same@Example.com", Groups: []string{"staff"}},
	}
	users := []syncUser{
		{UID: "john", syncSourceUser: syncSourceUser{Email: "john@b.com", GivenName: "Johnny"}},
		syncU("same"),
	}
	p := syncBuild(users, nil, ipa, syncTestConfig(nil), syncTestNow)
	syncCheck(t, "Enable", p.Enable, []string{"same"})
	syncCheck(t, "BackInGoogle", p.BackInGoogle, nil)
	want := "uid john belongs to john@a.com in FreeIPA but to john@b.com in Google; left alone"
	if len(p.Conflicts) != 1 || p.Conflicts[0] != want {
		t.Errorf("Conflicts = %v", p.Conflicts)
	}
	if len(p.Update) != 0 {
		t.Errorf("Update = %+v", p.Update)
	}
	if _, ok := p.RemoveGroups["john"]; ok {
		t.Error("conflicting user must get no group changes")
	}
	if len(p.Delete)+len(p.Disable)+len(p.NewMarkers) != 0 {
		t.Errorf("plan = %+v", p)
	}
}

func TestSyncBuildLockedNoGroupChanges(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"blocked": {UID: "blocked", Email: "blocked@example.com", Managed: true, Locked: true, Groups: []string{"admins"}},
		"found":   {UID: "found", Email: "found@example.com", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerFound, syncDay), Groups: []string{"admins"}},
		"reused":  {UID: "reused", Email: "reused@a.com", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, syncDay), Groups: []string{"admins"}},
		"adopted": {UID: "adopted", Email: "adopted@example.com", Locked: true},
		"back":    {UID: "back", Email: "back@example.com", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, syncDay), Groups: []string{"admins"}},
	}
	users := []syncUser{syncU("blocked", "dev@example.com"), syncU("found"), {UID: "reused", syncSourceUser: syncSourceUser{Email: "reused@b.com"}}, syncU("adopted"), syncU("back")}
	p := syncBuild(users, nil, ipa, syncTestConfig(func(c *syncConfig) { c.AdoptExisting = true }), syncTestNow)
	syncCheck(t, "Enable", p.Enable, []string{"back"})
	syncCheck(t, "Adopt", p.Adopt, []string{"adopted"})
	for _, uid := range []string{"blocked", "found", "reused", "adopted"} {
		if _, ok := p.AddGroups[uid]; ok {
			t.Errorf("AddGroups[%s] = %v", uid, p.AddGroups[uid])
		}
		if _, ok := p.RemoveGroups[uid]; ok {
			t.Errorf("RemoveGroups[%s] = %v", uid, p.RemoveGroups[uid])
		}
	}
	syncCheck(t, "AddGroups[back]", p.AddGroups["back"], []string{"staff"})
	syncCheck(t, "RemoveGroups[back]", p.RemoveGroups["back"], []string{"admins"})
}

func TestSyncBuildEmailConflictUnmanaged(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"old":  {UID: "old", Email: "old@a.com"},
		"same": {UID: "same", Email: "Same@Example.com"},
	}
	users := []syncUser{
		{UID: "old", syncSourceUser: syncSourceUser{Email: "old@b.com"}},
		syncU("same"),
	}
	p := syncBuild(users, nil, ipa, syncTestConfig(func(c *syncConfig) { c.AdoptExisting = true }), syncTestNow)
	syncCheck(t, "Adopt", p.Adopt, []string{"same"})
	if len(p.Conflicts) != 1 || !strings.Contains(p.Conflicts[0], "old@a.com") {
		t.Errorf("Conflicts = %v", p.Conflicts)
	}
	if _, ok := p.AddGroups["old"]; ok {
		t.Error("conflicting user must get no group changes")
	}
	if len(p.Update) != 0 {
		t.Errorf("Update = %+v", p.Update)
	}
}

func TestSyncBuildNoEmailConflict(t *testing.T) {
	ipa := map[string]syncIPAUser{
		// a service account without mail must not be handed to backup@ in Google
		"backup": {UID: "backup"},
		"gone":   {UID: "gone", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, time.Hour)},
	}
	p := syncBuild([]syncUser{syncU("backup"), syncU("gone")}, nil, ipa, syncTestConfig(func(c *syncConfig) { c.AdoptExisting = true }), syncTestNow)
	syncCheck(t, "Adopt", p.Adopt, nil)
	syncCheck(t, "Enable", p.Enable, nil)
	want := []string{
		"uid backup has no email in FreeIPA but belongs to backup@example.com in Google; left alone",
		"uid gone has no email in FreeIPA but belongs to gone@example.com in Google; left alone",
	}
	syncCheck(t, "Conflicts", p.Conflicts, want)
	if len(p.AddGroups)+len(p.Update) != 0 {
		t.Errorf("plan = %+v", p)
	}
}

func TestSyncBuildPreservedUserNeedsAdmin(t *testing.T) {
	ipa := map[string]syncIPAUser{"gone": {UID: "gone", Locked: true, Preserved: true}}
	p := syncBuild([]syncUser{syncU("gone")}, nil, ipa, syncTestConfig(func(c *syncConfig) { c.AdoptExisting = true }), syncTestNow)
	if len(p.Adopt)+len(p.Unmanaged)+len(p.Create) != 0 || len(p.Conflicts) != 1 || !strings.Contains(p.Conflicts[0], "user-undel") {
		t.Errorf("plan = %+v", p)
	}
}

func TestSyncPlanChanges(t *testing.T) {
	p := syncPlan{
		Create:       []syncUser{syncU("a")},
		Adopt:        []string{"b"},
		Update:       []syncUpdate{{UID: "c"}},
		Enable:       []string{"d"},
		Disable:      []string{"e"},
		Delete:       []string{"f"},
		AddGroups:    map[string][]string{"a": {"x", "y"}},
		RemoveGroups: map[string][]string{"c": {"z"}},
		NewMarkers:   map[string]syncMarker{"g": {Kind: syncMarkerFound}},
		BackInGoogle: []string{"h"},
		Conflicts:    []string{"i"},
		Unmanaged:    []string{"j"},
	}
	if got := p.Changes(); got != 9 {
		t.Errorf("Changes = %d, want 9", got)
	}
	if (syncPlan{}).Changes() != 0 || !(syncPlan{BackInGoogle: []string{"h"}, Conflicts: []string{"i"}}).Empty() {
		t.Error("informational lists are not changes")
	}
}

func TestSyncBuildBrakeNoFoundMarkers(t *testing.T) {
	ipa := map[string]syncIPAUser{"x": {UID: "x", Managed: true, Locked: true}}
	var users []syncUser
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		ipa[id] = syncIPAUser{UID: id, Email: id + "@example.com", Managed: true}
		users = append(users, syncU(id))
	}
	brake := syncTestConfig(func(c *syncConfig) { c.MaxDisablePercent = 20 })

	p := syncBuild(users, nil, ipa, brake, syncTestNow)
	if p.Braked || len(p.NewMarkers) != 1 {
		t.Fatalf("unbraked: %+v", p)
	}
	p = syncBuild(users[:7], nil, ipa, brake, syncTestNow)
	if !p.Braked || len(p.NewMarkers) != 0 {
		t.Fatalf("braked plan writes found markers: %+v", p.NewMarkers)
	}
}

func TestSyncBuildExcludedLockedUntouched(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"svc": {UID: "svc", Email: "svc@example.com", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, 90*syncDay), Groups: []string{"admins"}},
	}
	cfg := syncTestConfig(func(c *syncConfig) { c.ExcludeUsers = []string{"svc"} })
	for _, users := range [][]syncUser{nil, {syncU("svc")}} {
		p := syncBuild(users, nil, ipa, cfg, syncTestNow)
		if !p.Empty() {
			t.Errorf("excluded account planned changes (in Google: %v): %+v", users != nil, p)
		}
	}
}

func TestSyncBuildAdoptLocked(t *testing.T) {
	ipa := map[string]syncIPAUser{"legacy": {UID: "legacy", Email: "legacy@example.com", Locked: true, Groups: []string{"admins"}}}
	p := syncBuild([]syncUser{syncU("legacy")}, nil, ipa, syncTestConfig(func(c *syncConfig) { c.AdoptExisting = true }), syncTestNow)
	syncCheck(t, "Adopt", p.Adopt, []string{"legacy"})
	syncCheck(t, "Enable", p.Enable, nil)
	syncCheck(t, "BackInGoogle", p.BackInGoogle, nil)
	if len(p.AddGroups)+len(p.RemoveGroups)+len(p.Update) != 0 {
		t.Errorf("a locked account gets no changes beyond adoption: %+v", p)
	}
}

func TestSyncBuildSkippedLockedNotEnabled(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"jane": {UID: "jane", Email: "jane@example.com", Managed: true, Locked: true, Marker: syncMarkerAgo(syncMarkerSync, 90*syncDay)},
	}
	p := syncBuild(nil, []string{"jane"}, ipa, syncTestConfig(nil), syncTestNow)
	syncCheck(t, "Enable", p.Enable, nil)
	syncCheck(t, "Delete", p.Delete, nil)
	if p.Changes()+len(p.NewMarkers)+len(p.ClearMarkers) != 0 {
		t.Errorf("skipped uid planned changes: %+v", p)
	}
}

func TestSyncBuildCNDrift(t *testing.T) {
	ipa := map[string]syncIPAUser{
		"n":       {UID: "n", Email: "n@example.com", GivenName: "Nat", FamilyName: "Lee", FullName: "Nat Lee", CN: "nat by hand", Managed: true},
		"same":    {UID: "same", Email: "same@example.com", GivenName: "Nat", FamilyName: "Lee", FullName: "Nat Lee", CN: "Nat Lee", Managed: true},
		"unknown": {UID: "unknown", Email: "unknown@example.com", GivenName: "Nat", FamilyName: "Lee", FullName: "Nat Lee", Managed: true},
	}
	var users []syncUser
	for _, uid := range []string{"n", "same", "unknown"} {
		u := syncU(uid)
		u.GivenName, u.FamilyName, u.FullName = "Nat", "Lee", "Nat Lee"
		users = append(users, u)
	}
	p := syncBuild(users, nil, ipa, syncTestConfig(nil), syncTestNow)
	if len(p.Update) != 1 || p.Update[0].UID != "n" || p.Update[0].To.FullName != "Nat Lee" {
		t.Fatalf("Update = %+v", p.Update)
	}
}
