package server

import (
	"runtime/debug"
	"strings"
)

var Version = "dev"

// go install sets no ldflags, but stamps the module version into the binary.
func init() {
	if Version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		Version = strings.TrimPrefix(bi.Main.Version, "v")
	}
}

const (
	SessionKeyAuthenticated = "authenticated"
	SessionKeySID           = "sid"
	SessionKeyUsername      = "user"
	SessionKeyCSRF          = "csrf"
	ContextKeyUser          = "user"
	ContextKeyUsername      = "username"
	ContextKeyIPAClient     = "ipa"
	UserCategoryUnverified  = "mokey-user-unverified"
	UserCategoryPending     = "mokey-user-pending"
	TokenAccountVerify      = "verify"
	TokenPasswordReset      = "reset"
	TokenEmailChange        = "emailchange"
	TokenInvite             = "invite"
	TokenOTPRecovery        = "otprecovery"
	TokenUsedPrefix         = "used-"
	TokenIssuedPrefix       = "issued-"
	SessionKeyLoginTime     = "login_time"
	PasswordChangedPrefix   = "pwchanged-"
)
