package server

// Account lockout support via FreeIPA RPC methods goipa doesn't wrap:
// user_status (per-replica failed-login counters) and user_unlock.

import (
	"github.com/tidwall/gjson"
	ipa "github.com/ubccr/goipa"
)

// ipaAdminRPC runs a direct JSON-RPC call with the keytab-bound admin
// client. That client authenticates per-request via SPNEGO and normally has
// no session cookie (StickySession(false)), which the direct-RPC helper
// requires — so grab a fresh session with a Ping first and drop it after.
// ponytail: the sticky/session toggling races with concurrent requests on
// the shared client; worst case is a rare 401 on an admin RPC, which every
// caller already handles as an error.
func ipaAdminRPC(admin *ipa.Client, method string, params []string, options map[string]interface{}) (*ipa.Response, error) {
	admin.StickySession(true)
	defer func() {
		admin.ClearSession()
		admin.StickySession(false)
	}()

	if admin.SessionID() == "" {
		if _, err := admin.Ping(); err != nil {
			return nil, err
		}
	}

	return ipaSessionRPC(admin, method, params, options)
}

// userFailedLogins returns the highest krbloginfailedcount reported by any
// replica for the user
func userFailedLogins(client *ipa.Client, username string) (int, error) {
	res, err := ipaAdminRPC(client, "user_status", []string{username}, map[string]interface{}{
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
	_, err := ipaAdminRPC(client, "user_unlock", []string{username}, nil)
	return err
}

// PwPolicy is the password policy in effect for a user (pwpolicy_show).
// Zero values mean the attribute is unset in FreeIPA.
type PwPolicy struct {
	MinLength    int
	MinClasses   int
	HistorySize  int
	MaxLifeDays  int // pwpolicy_show reports max lifetime in days
	MinLifeHours int // ...and min lifetime in hours
	MaxFailure   int
}

// pwPolicyShow fetches the effective password policy for the user via the
// service bind (plain users lack the Password Policy Readers privilege)
func pwPolicyShow(client *ipa.Client, username string) (*PwPolicy, error) {
	res, err := ipaAdminRPC(client, "pwpolicy_show", []string{}, map[string]interface{}{
		"user": username,
	})
	if err != nil {
		return nil, err
	}

	data := gjson.ParseBytes(res.Result.Data)
	return &PwPolicy{
		MinLength:    int(data.Get("krbpwdminlength.0").Int()),
		MinClasses:   int(data.Get("krbpwdmindiffchars.0").Int()),
		HistorySize:  int(data.Get("krbpwdhistorylength.0").Int()),
		MaxLifeDays:  int(data.Get("krbmaxpwdlife.0").Int()),
		MinLifeHours: int(data.Get("krbminpwdlife.0").Int()),
		MaxFailure:   int(data.Get("krbpwdmaxfailure.0").Int()),
	}, nil
}

// userLockedOut reports whether the user has hit the failure lockout
// threshold of their password policy
func userLockedOut(client *ipa.Client, username string) bool {
	policy, err := pwPolicyShow(client, username)
	if err != nil || policy.MaxFailure <= 0 {
		return false
	}
	maxFail := policy.MaxFailure

	failed, err := userFailedLogins(client, username)
	if err != nil {
		return false
	}

	return failed >= maxFail
}
