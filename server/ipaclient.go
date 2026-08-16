package server

import (
	ipa "github.com/ubccr/goipa"
)

// FreeIPA client factories. Package-level vars so tests can point them at a
// fake FreeIPA server; production always uses the goipa defaults.
var (
	newIPAClient            = ipa.NewDefaultClient
	newIPAClientWithSession = ipa.NewDefaultClientWithSession
	ipaKeytabLogin          = func(c *ipa.Client, keytab, username string) error {
		return c.LoginWithKeytab(keytab, username)
	}
)
