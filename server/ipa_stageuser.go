// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"github.com/tidwall/gjson"
	ipa "github.com/ubccr/goipa"
)

// goipa has no stage-user support, so the stageuser_* JSON RPC commands are
// called directly through the admin client's FreeIPA session (same approach
// as passkeys, see ipa_passkey.go). The service account needs the
// "Stage User Administrators" privilege for these to succeed.

func stagedUserFromRecord(rec gjson.Result) *ipa.User {
	return &ipa.User{
		Username: rec.Get("uid.0").String(),
		Email:    rec.Get("mail.0").String(),
		First:    rec.Get("givenname.0").String(),
		Last:     rec.Get("sn.0").String(),
		Category: rec.Get("userclass.0").String(),
	}
}

func stageUserAdd(client *ipa.Client, user *ipa.User, password string) error {
	options := map[string]interface{}{
		"givenname":    user.First,
		"sn":           user.Last,
		"cn":           user.First + " " + user.Last,
		"mail":         user.Email,
		"userpassword": password,
		"userclass":    user.Category,
	}
	if user.HomeDir != "" {
		options["homedirectory"] = user.HomeDir
	}
	if user.Shell != "" {
		options["loginshell"] = user.Shell
	}
	_, err := ipaAdminRPC(client, "stageuser_add", []string{user.Username}, options)
	return err
}

func stageUserShow(client *ipa.Client, username string) (*ipa.User, error) {
	res, err := ipaAdminRPC(client, "stageuser_show", []string{username}, nil)
	if err != nil {
		return nil, err
	}
	return stagedUserFromRecord(gjson.ParseBytes(res.Result.Data)), nil
}

// stageUserFindPending lists staged signups that verified their email.
// stageuser_find matches loosely, so results are filtered to the exact
// pending category.
func stageUserFindPending(client *ipa.Client) ([]*ipa.User, error) {
	res, err := ipaAdminRPC(client, "stageuser_find", []string{}, map[string]interface{}{"sizelimit": 500})
	if err != nil {
		return nil, err
	}
	pending := []*ipa.User{}
	for _, rec := range gjson.ParseBytes(res.Result.Data).Array() {
		u := stagedUserFromRecord(rec)
		if u.Category == UserCategoryPending {
			pending = append(pending, u)
		}
	}
	return pending, nil
}

// stageUserSetCategory sets userclass; an empty category clears the
// attribute (FreeIPA mod semantics)
func stageUserSetCategory(client *ipa.Client, username, category string) error {
	_, err := ipaAdminRPC(client, "stageuser_mod", []string{username}, map[string]interface{}{"userclass": category})
	return err
}

// stageUserActivate turns the staged entry into an active account. FreeIPA
// marks the copied password expired, so the first login goes through the
// expired-password change flow.
func stageUserActivate(client *ipa.Client, username string) error {
	_, err := ipaAdminRPC(client, "stageuser_activate", []string{username}, nil)
	return err
}

func stageUserDel(client *ipa.Client, username string) error {
	_, err := ipaAdminRPC(client, "stageuser_del", []string{username}, nil)
	return err
}
