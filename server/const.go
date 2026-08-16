package server

var Version = "dev"

const (
	SessionKeyAuthenticated = "authenticated"
	SessionKeySID           = "sid"
	SessionKeyUsername      = "user"
	SessionKeyCSRF          = "csrf"
	ContextKeyUser          = "user"
	ContextKeyUsername      = "username"
	ContextKeyIPAClient     = "ipa"
	UserCategoryUnverified  = "mokey-user-unverified"
	TokenAccountVerify      = "verify"
	TokenPasswordReset      = "reset"
	TokenEmailChange        = "emailchange"
	TokenUsedPrefix         = "used-"
	TokenIssuedPrefix       = "issued-"
	SessionKeyLoginTime     = "login_time"
	PasswordChangedPrefix   = "pwchanged-"
)
