package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJoinPhone(t *testing.T) {
	assert := assert.New(t)

	// #22: arbitrary text used to be stored as-is
	for _, bad := range []string{"not a phone", "call me", "555-CALL", "++1"} {
		_, err := joinPhone("1", bad)
		assert.Error(err, "should reject %q", bad)
	}

	v, err := joinPhone("1", "505 555 0100")
	assert.NoError(err)
	assert.Equal("+1 505 555 0100", v)

	// a leading + on the code is tolerated
	v, err = joinPhone("+46", "701234567")
	assert.NoError(err)
	assert.Equal("+46 701234567", v)

	// clearing the number clears the attribute, no country code needed
	v, err = joinPhone("1", "")
	assert.NoError(err)
	assert.Equal("", v)
	v, err = joinPhone("", "")
	assert.NoError(err)
	assert.Equal("", v)

	// a number without a country code is refused...
	_, err = joinPhone("", "5055550100")
	assert.Error(err)

	// ...unless it carries its own
	v, err = joinPhone("", "+1 505 555 0100")
	assert.NoError(err)
	assert.Equal("+1 5055550100", v)

	// the country code itself has to look like one
	_, err = joinPhone("abc", "5055550100")
	assert.Error(err)
	_, err = joinPhone("12345", "5055550100")
	assert.Error(err)
}

func TestSplitPhone(t *testing.T) {
	assert := assert.New(t)

	code, national := splitPhone("+1 505 555 0100")
	assert.Equal("1", code)
	assert.Equal("505 555 0100", national)

	// values written outside mokey round-trip into the number field rather
	// than being silently dropped
	for _, legacy := range []string{"5055550100", "+15055550100", "ext 4021"} {
		code, national = splitPhone(legacy)
		assert.Equal("", code, "%q", legacy)
		assert.Equal(legacy, national, "%q", legacy)
	}

	code, national = splitPhone("")
	assert.Equal("", code)
	assert.Equal("", national)
}

// what mokey stores must survive a render/submit round trip untouched
func TestPhoneRoundTrip(t *testing.T) {
	assert := assert.New(t)
	for _, stored := range []string{"+1 505 555 0100", "+46 701234567", "+380 671234567"} {
		code, national := splitPhone(stored)
		again, err := joinPhone(code, national)
		assert.NoError(err)
		assert.Equal(stored, again)
	}
}

// the picker is built from the ISO 3166 / E.164 tables rather than a
// hand-kept list, so this only guards the shape we depend on
func TestPhoneCountries(t *testing.T) {
	assert := assert.New(t)
	all := PhoneCountries()

	assert.Greater(len(all), 200)

	byAlpha2 := map[string]PhoneCountry{}
	for i, c := range all {
		assert.NotEmpty(c.Name, "entry %d", i)
		assert.NotEmpty(c.Code, "%s has no dial code", c.Name)
		assert.True(isDigits(c.Code), "%s dial code %q is not digits", c.Name, c.Code)
		assert.NotEmpty(c.Flag, "%s has no flag", c.Name)
		if i > 0 {
			assert.LessOrEqual(all[i-1].Name, c.Name, "list must be sorted by name")
		}
		byAlpha2[c.Alpha2] = c
	}

	assert.Equal("1", byAlpha2["US"].Code)
	assert.Equal("380", byAlpha2["UA"].Code)
	assert.Equal("🇺🇦", byAlpha2["UA"].Flag)
	assert.Equal("Ukraine", byAlpha2["UA"].Name)

	// the stored dial code maps back to a flag for the closed picker
	assert.Equal("🇺🇦", PhoneFlag("380"))
	assert.Equal("", PhoneFlag("99999"))
}

// nine dial codes are shared; the flag shown for a stored number must be the
// country, not whichever territory happens to sort first
func TestPhoneFlagPrefersTheCountryOverItsTerritories(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("🇺🇸", PhoneFlag("1"), "+1 is Canada, the US and two territories")
	assert.Equal("🇷🇺", PhoneFlag("7"))
	assert.Equal("🇳🇴", PhoneFlag("47"))
	assert.Equal("🇦🇺", PhoneFlag("61"))
	assert.Equal("🇳🇿", PhoneFlag("64"))

	// unambiguous codes are unaffected
	assert.Equal("🇺🇦", PhoneFlag("380"))
	assert.Equal("🇬🇧", PhoneFlag("44"))

	// every tie-break must name a country that actually holds that code
	for code, alpha2 := range primaryForSharedCode {
		found := false
		for _, c := range PhoneCountries() {
			if c.Code == code && c.Alpha2 == alpha2 {
				found = true
				break
			}
		}
		assert.True(found, "+%s is not held by %s", code, alpha2)
	}
}
