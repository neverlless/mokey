package server

import (
	"slices"
	"strings"
)

// syncRuleAttrs are the source attributes a rule may match on.
var syncRuleAttrs = []string{"org_unit", "department", "title", "cost_center", "email_domain"}

// syncRule puts users whose attributes match every condition into Groups.
// Conds maps an attribute to accepted values: AND across attributes, OR
// within one.
type syncRule struct {
	Name   string
	Conds  map[string][]string
	Groups []string
}

// syncOUWithin is true when path is ou or one of its sub-OUs; the root
// "/" holds every non-empty path.
func syncOUWithin(path, ou string) bool {
	if syncName(path) == "" {
		return false
	}
	path, ou = strings.TrimRight(syncName(path), "/"), strings.TrimRight(syncName(ou), "/")
	return path == ou || strings.HasPrefix(path, ou+"/")
}

func (r syncRule) matches(attrs map[string]string) bool {
	if len(r.Conds) == 0 {
		return false
	}
	for attr, values := range r.Conds {
		v := syncName(attrs[attr])
		// a missing or empty attribute never matches, not even OU "/"
		if v == "" || !slices.ContainsFunc(values, func(want string) bool {
			if attr == "org_unit" {
				return syncOUWithin(v, want)
			}
			return v == syncName(want)
		}) {
			return false
		}
	}
	return true
}

// ruleGroups returns the sorted groups the matching rules target and, per
// group, the names of the rules that want it.
func ruleGroups(rules []syncRule, attrs map[string]string) (groups []string, reasons map[string][]string) {
	reasons = map[string][]string{}
	for _, r := range rules {
		if !r.matches(attrs) {
			continue
		}
		for _, g := range r.Groups {
			if !slices.Contains(reasons[g], r.Name) {
				reasons[g] = append(reasons[g], r.Name)
			}
			if !slices.Contains(groups, g) {
				groups = append(groups, g)
			}
		}
	}
	slices.Sort(groups)
	return groups, reasons
}
