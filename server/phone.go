// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"errors"
	"sort"
	"strconv"
	"strings"

	valid "github.com/asaskevich/govalidator"
	"github.com/biter777/countries"
)

// Phone numbers are stored as "+<dial code> <national number>" so the two
// halves of the form can be recovered on the next render. FreeIPA keeps the
// attribute free-form, so values written before this format existed (or by
// ipa(1) directly) still have to round-trip.

// splitPhone recovers the dial code and national number from a stored value.
// Anything that does not match the stored format is handed back whole as the
// national number, so an externally set value is shown rather than dropped.
func splitPhone(stored string) (code, national string) {
	stored = strings.TrimSpace(stored)
	if !strings.HasPrefix(stored, "+") {
		return "", stored
	}

	code, national, found := strings.Cut(stored[1:], " ")
	if !found || code == "" || !isDigits(code) {
		return "", stored
	}

	return code, strings.TrimSpace(national)
}

// joinPhone builds the stored value from the two form fields. An empty
// national number clears the attribute. A number given on its own is accepted
// only when it already carries its own country code.
func joinPhone(code, national string) (string, error) {
	code = strings.TrimPrefix(strings.TrimSpace(code), "+")
	national = strings.TrimSpace(national)

	if national == "" {
		return "", nil
	}

	if code == "" {
		// a full international number pasted into the number field
		if strings.HasPrefix(national, "+") && isPhoneish(national[1:]) && valid.IsE164(compactPhone(national)) {
			code, national = splitCompact(compactPhone(national))
			return "+" + code + " " + national, nil
		}
		return "", errors.New(T("account.phone_needs_country_code"))
	}

	if !isDigits(code) || len(code) > 4 {
		return "", errors.New(T("account.phone_invalid_country_code"))
	}

	// Check the characters before compacting: digitsOnly would quietly
	// strip the letters out of "555-CALL" and accept what is left.
	if !isPhoneish(national) || !valid.IsE164("+"+code+digitsOnly(national)) {
		return "", errors.New(T("account.phone_invalid"))
	}

	return "+" + code + " " + national, nil
}

// splitCompact takes the leading digit off a compact E.164 number as the dial
// code. Code lengths are ambiguous without a country table, so this is only
// used to normalise a number the user typed with its own "+" — the split is
// cosmetic and the stored value round-trips either way.
func splitCompact(compact string) (code, national string) {
	digits := strings.TrimPrefix(compact, "+")
	return digits[:1], digits[1:]
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
