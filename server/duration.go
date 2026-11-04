// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"fmt"
	"strings"
	"time"
)

var durationUnits = []struct {
	name string
	size time.Duration
}{
	{"year", 365 * 24 * time.Hour},
	{"month", 30 * 24 * time.Hour},
	{"week", 7 * 24 * time.Hour},
	{"day", 24 * time.Hour},
	{"hour", time.Hour},
	{"minute", time.Minute},
	{"second", time.Second},
}

// pluralForm is the CLDR plural category of n in lang: one/few/many for
// Russian and Ukrainian, one/other for everything else.
func pluralForm(lang string, n int) string {
	switch code, _, _ := strings.Cut(languageCodes[lang], "-"); code {
	case "ru", "uk":
		switch {
		case n%10 == 1 && n%100 != 11:
			return "one"
		case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
			return "few"
		}
		return "many"
	}
	if n == 1 {
		return "one"
	}
	return "other"
}

// formatDuration renders d in lang floored to its largest whole unit, as
// "2 days".
func formatDuration(lang string, d time.Duration) string {
	d = d.Abs()
	unit := durationUnits[len(durationUnits)-1]
	for _, u := range durationUnits {
		if d >= u.size {
			unit = u
			break
		}
	}

	n := int(d / unit.size)
	key := "duration." + unit.name + "_"
	format, ok := translations[lang][key+pluralForm(lang, n)]
	if !ok {
		// the english forms are one/other whatever lang's plural rule is
		format = TL(lang, key+pluralForm("english", n))
	}
	return fmt.Sprintf(format, n)
}

// timeAgo renders t relative to now in lang: "3 hours ago", "2 days from now".
func timeAgo(lang string, t time.Time) string {
	d := time.Since(t)
	switch {
	case d.Abs() < time.Second:
		return TL(lang, "duration.now")
	case d < 0:
		return fmt.Sprintf(TL(lang, "duration.from_now"), formatDuration(lang, d))
	}
	return fmt.Sprintf(TL(lang, "duration.ago"), formatDuration(lang, d))
}
