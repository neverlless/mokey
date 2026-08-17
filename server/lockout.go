package server

// Account lockout support via FreeIPA RPC methods goipa doesn't wrap:
// user_status (per-replica failed-login counters) and user_unlock.

import (
	"github.com/tidwall/gjson"
	ipa "github.com/ubccr/goipa"
)

// userFailedLogins returns the highest krbloginfailedcount reported by any
// replica for the user
func userFailedLogins(client *ipa.Client, username string) (int, error) {
	res, err := ipaPasskeyRPC(client, "user_status", []string{username}, map[string]interface{}{
		"all": true,
	})
	if err != nil {
		return 0, err
	}

	failed := 0
	gjson.ParseBytes(res.Result.Data).ForEach(func(_, entry gjson.Result) bool {
		if n := int(entry.Get("krbloginfailedcount.0").Int()); n > failed {
			failed = n
		}
		return true
	})

	return failed, nil
}

// userUnlock clears the failed-login lockout state for the user on all
// replicas (FreeIPA user_unlock)
func userUnlock(client *ipa.Client, username string) error {
	_, err := ipaPasskeyRPC(client, "user_unlock", []string{username}, nil)
	return err
}

// pwPolicyMaxFailure returns the krbpwdmaxfailure of the password policy in
// effect for the user; 0 means lockout is disabled or unknown
func pwPolicyMaxFailure(client *ipa.Client, username string) int {
	res, err := ipaPasskeyRPC(client, "pwpolicy_show", []string{}, map[string]interface{}{
		"user": username,
	})
	if err != nil {
		return 0
	}

	return int(gjson.ParseBytes(res.Result.Data).Get("krbpwdmaxfailure.0").Int())
}

// userLockedOut reports whether the user has hit the failure lockout
// threshold of their password policy
func userLockedOut(client *ipa.Client, username string) bool {
	maxFail := pwPolicyMaxFailure(client, username)
	if maxFail <= 0 {
		return false
	}

	failed, err := userFailedLogins(client, username)
	if err != nil {
		return false
	}

	return failed >= maxFail
}
