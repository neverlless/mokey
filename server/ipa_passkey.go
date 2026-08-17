// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/tidwall/gjson"
	ipa "github.com/ubccr/goipa"
)

// goipa has no passkey support and keeps its rpc method private, so the
// user_add_passkey / user_remove_passkey / user_show calls are made here
// directly, reusing the FreeIPA session of an already authenticated goipa
// client. Managing your own passkey mappings requires the FreeIPA
// self-service permission introduced with passkey support in FreeIPA 4.11.
func ipaPasskeyRPC(client *ipa.Client, method string, params []string, options map[string]interface{}) (*ipa.Response, error) {
	if client.SessionID() == "" {
		return nil, fmt.Errorf("passkey rpc requires an authenticated FreeIPA session")
	}

	if options == nil {
		options = map[string]interface{}{}
	}
	options["version"] = ipa.IpaClientVersion

	payload := map[string]interface{}{
		"id":     0,
		"method": method,
		"params": []interface{}{params, options},
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/ipa/session/json", client.Host()), bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", fmt.Sprintf("https://%s/ipa/xml", client.Host()))
	req.Header.Set("Cookie", fmt.Sprintf("ipa_session=%s", client.SessionID()))

	res, err := ipaRPCHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IPA passkey RPC failed with HTTP status code: %d", res.StatusCode)
	}

	rawJSON, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var ipaRes ipa.Response
	if err := json.Unmarshal(rawJSON, &ipaRes); err != nil {
		return nil, err
	}
	if ipaRes.Error != nil {
		return nil, ipaRes.Error
	}

	return &ipaRes, nil
}

func userAddPasskey(client *ipa.Client, uid, mapping string) error {
	_, err := ipaPasskeyRPC(client, "user_add_passkey", []string{uid, mapping}, nil)
	return err
}

func userRemovePasskey(client *ipa.Client, uid, mapping string) error {
	_, err := ipaPasskeyRPC(client, "user_remove_passkey", []string{uid, mapping}, nil)
	return err
}

func userPasskeys(client *ipa.Client, uid string) ([]string, error) {
	res, err := ipaPasskeyRPC(client, "user_show", []string{uid}, map[string]interface{}{"all": true})
	if err != nil {
		return nil, err
	}

	var mappings []string
	for _, v := range gjson.GetBytes(res.Result.Data, "ipapasskey").Array() {
		mappings = append(mappings, v.String())
	}

	return mappings, nil
}

// passkeyMapping builds a FreeIPA passkey mapping string
// (passkey:<credId b64>,<pubkey SPKI b64>) from a WebAuthn credential ID and
// its COSE-encoded public key.
func passkeyMapping(credentialID, cosePublicKey []byte) (string, error) {
	parsed, err := webauthncose.ParsePublicKey(cosePublicKey)
	if err != nil {
		return "", err
	}

	var pub interface{}
	switch key := parsed.(type) {
	case webauthncose.EC2PublicKeyData:
		var curve elliptic.Curve
		switch webauthncose.COSEEllipticCurve(key.Curve) {
		case webauthncose.P256:
			curve = elliptic.P256()
		case webauthncose.P384:
			curve = elliptic.P384()
		case webauthncose.P521:
			curve = elliptic.P521()
		default:
			return "", fmt.Errorf("unsupported elliptic curve: %d", key.Curve)
		}
		pub = &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(key.XCoord),
			Y:     new(big.Int).SetBytes(key.YCoord),
		}
	case webauthncose.RSAPublicKeyData:
		pub = &rsa.PublicKey{
			N: new(big.Int).SetBytes(key.Modulus),
			E: int(new(big.Int).SetBytes(key.Exponent).Int64()),
		}
	case webauthncose.OKPPublicKeyData:
		pub = ed25519.PublicKey(key.XCoord)
	default:
		return "", fmt.Errorf("unsupported public key type %T", parsed)
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("passkey:%s,%s",
		base64.StdEncoding.EncodeToString(credentialID),
		base64.StdEncoding.EncodeToString(spki)), nil
}
