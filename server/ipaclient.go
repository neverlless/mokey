package server

import (
	"net/http"

	ipa "github.com/ubccr/goipa"
)

// FreeIPA client factories. Package-level vars so tests can point them at a
// fake FreeIPA server; production always uses the goipa defaults.
var (
	// HTTP client for direct JSON-RPC calls (passkeys, user_status, ...)
	ipaRPCHTTPClient = http.DefaultClient

	newIPAClient            = ipa.NewDefaultClient
	newIPAClientWithSession = ipa.NewDefaultClientWithSession
	ipaKeytabLogin          = func(c *ipa.Client, keytab, username string) error {
		return c.LoginWithKeytab(keytab, username)
	}
)
