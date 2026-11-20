package server

import (
	"maps"
	"slices"
	"testing"
)

func TestSyncRuleMatches(t *testing.T) {
	attrs := map[string]string{
		"org_unit":     "/research/lab",
		"department":   "engineering",
		"title":        "sre",
		"email_domain": "example.org",
	}
	for _, tc := range []struct {
		name  string
		conds map[string][]string
		want  bool
	}{
		{"ou exact", map[string][]string{"org_unit": {"/research/lab"}}, true},
		{"ou parent", map[string][]string{"org_unit": {"/research"}}, true},
		{"ou parent trailing slash", map[string][]string{"org_unit": {"/research/"}}, true},
		{"ou root", map[string][]string{"org_unit": {"/"}}, true},
		{"ou case and space", map[string][]string{"org_unit": {" /Research "}}, true},
		{"ou not segment", map[string][]string{"org_unit": {"/res"}}, false},
		{"ou child of user", map[string][]string{"org_unit": {"/research/lab/deep"}}, false},
		{"department case", map[string][]string{"department": {"Engineering"}}, true},
		{"department no prefix", map[string][]string{"department": {"Eng"}}, false},
		{"or within condition", map[string][]string{"department": {"sales", "engineering"}}, true},
		{"and across conditions", map[string][]string{"department": {"engineering"}, "title": {"sre"}}, true},
		{"and fails on one", map[string][]string{"department": {"engineering"}, "title": {"manager"}}, false},
		{"missing attribute", map[string][]string{"cost_center": {"cc1"}}, false},
		{"email domain", map[string][]string{"email_domain": {"Example.org"}}, true},
		{"no conditions", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (syncRule{Name: "r", Conds: tc.conds, Groups: []string{"g"}}).matches(attrs); got != tc.want {
				t.Fatalf("matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSyncRuleEmptyAttributeNeverMatches(t *testing.T) {
	r := syncRule{Name: "r", Conds: map[string][]string{"department": {""}, "org_unit": {"/"}}, Groups: []string{"g"}}
	if r.matches(map[string]string{"department": "", "org_unit": "/x"}) {
		t.Fatal("an empty department must not match")
	}
	if (syncRule{Conds: map[string][]string{"org_unit": {"/"}}}).matches(map[string]string{"org_unit": " "}) {
		t.Fatal("an empty org unit must not match even the root")
	}
	if (syncRule{Conds: map[string][]string{"org_unit": {"/"}}}).matches(nil) {
		t.Fatal("nil attributes must not match")
	}
}

func TestSyncRuleGroups(t *testing.T) {
	rules := []syncRule{
		{Name: "research", Conds: map[string][]string{"org_unit": {"/research"}}, Groups: []string{"hpc", "staff"}},
		{Name: "sre", Conds: map[string][]string{"title": {"sre"}}, Groups: []string{"hpc"}},
		{Name: "sales", Conds: map[string][]string{"department": {"sales"}}, Groups: []string{"crm"}},
	}
	groups, reasons := ruleGroups(rules, map[string]string{"org_unit": "/Research", "title": "SRE"})
	if !slices.Equal(groups, []string{"hpc", "staff"}) {
		t.Fatalf("groups = %v", groups)
	}
	want := map[string][]string{"hpc": {"research", "sre"}, "staff": {"research"}}
	if !maps.EqualFunc(reasons, want, slices.Equal) {
		t.Fatalf("reasons = %v", reasons)
	}
	if g, r := ruleGroups(rules, nil); g != nil || len(r) != 0 {
		t.Fatalf("no attrs: %v %v", g, r)
	}
}

func TestSyncOUWithin(t *testing.T) {
	for _, tc := range []struct {
		path, ou string
		want     bool
	}{
		{"/research", "/research/", true},
		{"/research/", "/research", true},
		{"/research/lab", "/research/", true},
		{"/x", "/", true},
		{"/", "/", true},
		{"/researchops", "/research/", false},
		{"/", "/research", false},
		{"", "/", false},
	} {
		if got := syncOUWithin(tc.path, tc.ou); got != tc.want {
			t.Errorf("syncOUWithin(%q, %q) = %v, want %v", tc.path, tc.ou, got, tc.want)
		}
	}
}
