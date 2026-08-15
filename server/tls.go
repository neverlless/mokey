// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/tls"
	"fmt"

	"github.com/spf13/viper"
)

// tlsVersionFromConfig maps the server.tls_min_version config value to a
// crypto/tls version constant. Defaults to TLS 1.2.
func tlsVersionFromConfig() (uint16, error) {
	switch v := viper.GetString("server.tls_min_version"); v {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("invalid config value for tls_min_version: %s", v)
	}
}

// cipherSuitesFromConfig maps cipher suite names from server.tls_ciphers to
// crypto/tls cipher suite IDs. Returns nil if the option is not set, which
// lets crypto/tls use its default secure set. Note: Go does not allow
// configuring TLS 1.3 cipher suites; this list only applies to TLS 1.2.
func cipherSuitesFromConfig() ([]uint16, error) {
	names := viper.GetStringSlice("server.tls_ciphers")
	if len(names) == 0 {
		return nil, nil
	}

	byName := make(map[string]uint16)
	for _, cs := range tls.CipherSuites() {
		byName[cs.Name] = cs.ID
	}
	for _, cs := range tls.InsecureCipherSuites() {
		byName[cs.Name] = cs.ID
	}

	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		id, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown cipher suite in tls_ciphers: %s", name)
		}
		ids = append(ids, id)
	}

	return ids, nil
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return nil, err
	}

	minVersion, err := tlsVersionFromConfig()
	if err != nil {
		return nil, err
	}

	ciphers, err := cipherSuitesFromConfig()
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
		CipherSuites: ciphers,
	}, nil
}
