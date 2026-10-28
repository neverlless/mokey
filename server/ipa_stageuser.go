// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"time"

	ipa "github.com/neverlless/goipa"
	log "github.com/sirupsen/logrus"
)

// The service account needs the "Stage User Administrators" privilege for
// these to succeed.

func stageUserAdd(client *ipa.Client, user *ipa.User, password string) error {
	_, err := client.StageUserAddWithPassword(user, password)
	return err
}

func stageUserShow(client *ipa.Client, username string) (*ipa.User, error) {
	return client.StageUserShow(username)
}

// stageUserFindPending lists staged signups that verified their email.
// stageuser_find matches loosely, so results are filtered to the exact
// pending category. all=true is required: the default find output leaves
// out userclass, which would filter every record away (#46).
func stageUserFindPending(client *ipa.Client) ([]*ipa.User, error) {
	staged, err := client.StageUserFind(ipa.Options{"sizelimit": 500})
	if err != nil {
		return nil, err
	}
	pending := []*ipa.User{}
	for _, u := range staged {
		if u.Category == UserCategoryPending {
			pending = append(pending, u)
		}
	}
	return pending, nil
}

// stageUserSetCategory sets userclass; an empty category clears the
// attribute (FreeIPA mod semantics)
func stageUserSetCategory(client *ipa.Client, username, category string) error {
	_, err := client.Modify("stageuser_mod", username).Set("userclass", category).Run(context.Background())
	return err
}

// ipaDatetimeLayout is the generalized-time format FreeIPA accepts for
// datetime attributes passed through setattr
const ipaDatetimeLayout = "20060102150405Z"

// stageUserActivate turns the staged entry into an active account, then lifts
// the expiry FreeIPA stamps on the copied password.
func stageUserActivate(client *ipa.Client, username string) error {
	if _, err := client.StageUserActivate(username); err != nil {
		return err
	}

	clearNewPasswordExpiry(client, username)
	return nil
}

// clearNewPasswordExpiry undoes FreeIPA's "new passwords expired" marking for
// an activated signup. That rule exists because an admin-set password is a
// secret the owner did not choose; here the owner chose it themselves at
// registration and it was validated against the live password policy, so all
// the forced change buys is a confusing first login (ubccr/mokey#15).
//
// Best effort: if this fails the user simply gets the expired-password change
// flow they would have got anyway, so activation is not rolled back.
func clearNewPasswordExpiry(client *ipa.Client, username string) {
	// Honour the policy's max lifetime; an unset one means passwords never
	// expire, and an empty setattr value removes the attribute.
	expiration := ""
	if policy, err := pwPolicyShow(client, username); err == nil && policy.MaxLifeDays > 0 {
		expiration = time.Now().UTC().AddDate(0, 0, policy.MaxLifeDays).Format(ipaDatetimeLayout)
	}

	_, err := client.Modify("user_mod", username).Set("krbPasswordExpiration", expiration).Run(context.Background())
	if err != nil {
		log.WithFields(log.Fields{
			"username": username,
			"err":      err,
		}).Warn("Failed to clear new-password expiry; user will be asked to change it on first login")
	}
}

func stageUserDel(client *ipa.Client, username string) error {
	return client.StageUserDelete(username)
}
