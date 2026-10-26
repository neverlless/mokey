// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	ipa "github.com/neverlless/goipa"
)

// Generating a range for another user requires the "Subordinate ID
// Administrators" privilege on the service account.

type subidRange struct {
	SubUID int64
	SubGID int64
	Count  int64
}

// subidFind returns the user's subordinate id range, or nil when none is
// allocated (FreeIPA enforces at most one range per user)
func subidFind(client *ipa.Client, username string) (*subidRange, error) {
	subs, err := client.SubIDFind(ipa.Options{"ipaowner": username})
	if err != nil {
		return nil, err
	}
	if len(subs) == 0 {
		return nil, nil
	}
	return &subidRange{
		SubUID: subs[0].UIDStart,
		SubGID: subs[0].GIDStart,
		Count:  subs[0].UIDCount,
	}, nil
}

func subidGenerate(client *ipa.Client, username string) error {
	_, err := client.SubIDGenerate(username)
	return err
}
