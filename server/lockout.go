package server

import (
	"time"

	ipa "github.com/neverlless/goipa"
)

// userFailedLogins returns the highest krbloginfailedcount reported by any
// replica for the user
func userFailedLogins(client *ipa.Client, username string) (int, error) {
	replicas, err := client.UserStatus(username)
	if err != nil {
		return 0, err
	}

	failed := 0
	for _, r := range replicas {
		failed = max(failed, r.FailedLogins)
	}

	return failed, nil
}

// userUnlock clears the failed-login lockout state for the user on all
// replicas (FreeIPA user_unlock)
func userUnlock(client *ipa.Client, username string) error {
	return client.UserUnlock(username)
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
// service bind (plain users lack the Password Policy Readers privilege). An
// empty username returns the global policy, which is the best we can do for
// an account that does not exist yet.
func pwPolicyShow(client *ipa.Client, username string) (*PwPolicy, error) {
	var (
		p   *ipa.PwPolicy
		err error
	)
	if username != "" {
		p, err = client.UserPwPolicy(username)
	} else {
		p, err = client.PwPolicyShow("")
	}
	if err != nil {
		return nil, err
	}

	return &PwPolicy{
		MinLength:    p.MinLength,
		MinClasses:   p.MinClasses,
		HistorySize:  p.HistoryLength,
		MaxLifeDays:  int(p.MaxLife / (24 * time.Hour)),
		MinLifeHours: int(p.MinLife / time.Hour),
		MaxFailure:   p.MaxFailures,
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
