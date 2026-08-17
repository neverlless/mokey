// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"github.com/tidwall/gjson"
	ipa "github.com/ubccr/goipa"
)

// goipa has no subordinate-id support, so the subid_* commands go through
// the direct session RPC (see ipa_passkey.go). Generating a range for
// another user requires the "Subordinate ID Administrators" privilege on
// the service account.

type subidRange struct {
	SubUID int64
	SubGID int64
	Count  int64
}

func subidFromRecord(rec gjson.Result) *subidRange {
	return &subidRange{
		SubUID: rec.Get("ipasubuidnumber.0").Int(),
		SubGID: rec.Get("ipasubgidnumber.0").Int(),
		Count:  rec.Get("ipasubuidcount.0").Int(),
	}
}

// subidFind returns the user's subordinate id range, or nil when none is
// allocated (FreeIPA enforces at most one range per user)
func subidFind(client *ipa.Client, username string) (*subidRange, error) {
	res, err := ipaAdminRPC(client, "subid_find", []string{}, map[string]interface{}{
		"ipaowner": username,
	})
	if err != nil {
		return nil, err
	}
	recs := gjson.ParseBytes(res.Result.Data).Array()
	if len(recs) == 0 {
		return nil, nil
	}
	return subidFromRecord(recs[0]), nil
}

func subidGenerate(client *ipa.Client, username string) error {
	_, err := ipaAdminRPC(client, "subid_generate", []string{}, map[string]interface{}{
		"ipaowner": username,
	})
	return err
}
