package server

import (
	ipa "github.com/neverlless/goipa"
)

// FreeIPA client factories. Package-level vars so tests can point them at a
// fake FreeIPA server; production always uses the goipa defaults.
var (
	newIPAClient            = func() (*ipa.Client, error) { return ipa.New() }
	newIPAClientWithSession = func(sid string) (*ipa.Client, error) {
		c, err := ipa.New()
		if err != nil {
			return nil, err
		}
		c.SetSessionID(sid)
		return c, nil
	}
	ipaKeytabLogin = func(c *ipa.Client, keytab, username string) error {
		return c.LoginWithKeytab(keytab, username)
	}
)
