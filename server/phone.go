// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/biter777/countries"
)

// Phone numbers are stored in E.164 form, "+<dial code><digits>", which is what
// FreeIPA and other directory clients expect. Values written by earlier
// releases have a space after the dial code ("+380 123456789"); FreeIPA keeps
// the attribute free-form, so those and values set by ipa(1) still have to
// round-trip.

// splitPhone recovers the dial code and national number from a stored value.
// Anything that does not match a stored format is handed back whole as the
// national number, so an externally set value is shown rather than dropped.
func splitPhone(stored string) (code, national string) {
	stored = strings.TrimSpace(stored)
	if !strings.HasPrefix(stored, "+") {
		return "", stored
	}

	if code, national, found := strings.Cut(stored[1:], " "); found {
		if code == "" || !isDigits(code) {
			return "", stored
		}
		return code, strings.TrimSpace(national)
	}

	if code, national, ok := splitCompact(stored); ok {
		return code, national
	}
	return "", stored
}

// joinPhone builds the stored value from the two form fields. An empty
// national number clears the attribute. A number that starts with "+" carries
// its own country code, which wins over the picker.
func joinPhone(lang, code, national string) (string, error) {
	code = strings.TrimPrefix(strings.TrimSpace(code), "+")
	national = strings.TrimSpace(national)

	if national == "" {
		return "", nil
	}

	if strings.HasPrefix(national, "+") {
		compact := compactPhone(national)
		if !isPhoneish(national[1:]) || !isE164(compact) {
			return "", errors.New(TL(lang, "account.phone_invalid"))
		}
		if _, _, ok := splitCompact(compact); !ok {
			return "", errors.New(TL(lang, "account.phone_invalid_country_code"))
		}
		return compact, nil
	}

	if code == "" {
		return "", errors.New(TL(lang, "account.phone_needs_country_code"))
	}

	if !isDigits(code) || len(code) > 4 {
		return "", errors.New(TL(lang, "account.phone_invalid_country_code"))
	}

	// Check the characters before compacting: digitsOnly would quietly
	// strip the letters out of "555-CALL" and accept what is left.
	if !isPhoneish(national) || !isE164("+"+code+digitsOnly(national)) {
		return "", errors.New(TL(lang, "account.phone_invalid"))
	}

	return "+" + code + digitsOnly(national), nil
}

// splitCompact splits "+<code><national>" by the longest prefix that is a
// real dial code from the country table.
func splitCompact(compact string) (code, national string, ok bool) {
	digits := strings.TrimPrefix(compact, "+")
	if !isDigits(digits) {
		return "", "", false
	}
	for n := min(4, len(digits)-1); n >= 1; n-- {
		if dialCodes[digits[:n]] {
			return digits[:n], digits[n:], true
		}
	}
	return "", "", false
}

func compactPhone(s string) string {
	return "+" + digitsOnly(s)
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isPhoneish reports whether s is made only of the punctuation people write
// numbers with, and holds at least one digit
func isPhoneish(s string) bool {
	seenDigit := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			seenDigit = true
		case r == ' ' || r == '-' || r == '.' || r == '(' || r == ')':
		default:
			return false
		}
	}
	return seenDigit
}

// isE164 checks the "+<digits>" form only: callers always add the plus
func isE164(s string) bool {
	d, ok := strings.CutPrefix(s, "+")
	return ok && len(d) >= 2 && len(d) <= 15 && d[0] != '0' && isDigits(d)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	return digitsOnly(s) == s
}

// PhoneCode and PhoneNumber feed the two halves of the phone fields back
// into the form on render
func PhoneCode(stored string) string {
	code, _ := splitPhone(stored)
	return code
}

func PhoneNumber(stored string) string {
	_, national := splitPhone(stored)
	return national
}

// PhoneCountry is one entry of the country-code picker.
type PhoneCountry struct {
	Name   string
	Alpha2 string
	Code   string // ITU-T E.164 dial code, digits only
	Flag   string // Unicode regional-indicator pair
}

// phoneCountries is the picker list, built once from the ISO 3166 / E.164
// tables in biter777/countries. Several countries share a dial code (+1 has
// two dozen), so the first match wins when a stored number is mapped back to
// a flag — the number is what matters, the flag is a label.
var phoneCountries = buildPhoneCountries()

var dialCodes = func() map[string]bool {
	m := make(map[string]bool, len(phoneCountries))
	for _, c := range phoneCountries {
		m[c.Code] = true
	}
	return m
}()

func buildPhoneCountries() []PhoneCountry {
	out := make([]PhoneCountry, 0, countries.Total())
	for _, c := range countries.All() {
		codes := c.CallCodes()
		if len(codes) == 0 || codes[0] == 0 {
			continue
		}
		name := c.String()
		if name == "" || name == countries.Unknown.String() {
			continue
		}
		out = append(out, PhoneCountry{
			Name:   name,
			Alpha2: c.Alpha2(),
			Code:   strconv.Itoa(int(codes[0])),
			Flag:   c.Emoji(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// PhoneCountries feeds the country-code picker.
func PhoneCountries() []PhoneCountry { return phoneCountries }

// Nine dial codes are shared, in every case between one country and one or
// more dependencies or uninhabited territories (+1 also covers the French
// Southern Territories, +61 Heard Island, +672 Antarctica). A stored number
// only carries the code, so re-rendering the picker has to pick one to show:
// name the country here rather than let alphabetical order decide and label a
// US number with the Canadian flag. Display only — the stored number and the
// picker list are untouched.
var primaryForSharedCode = map[string]string{
	"1":   "US",
	"7":   "RU",
	"47":  "NO",
	"61":  "AU",
	"64":  "NZ",
	"212": "MA",
	"500": "FK",
	"590": "GP",
	"672": "NF",
}

// PhoneFlag returns the flag for a dial code, or "" when nothing matches.
func PhoneFlag(code string) string {
	primary := primaryForSharedCode[code]
	var first string
	for _, c := range phoneCountries {
		if c.Code != code {
			continue
		}
		if c.Alpha2 == primary {
			return c.Flag
		}
		if first == "" {
			first = c.Flag
		}
	}
	return first
}
