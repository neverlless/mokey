// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	ipa "github.com/neverlless/goipa"
)

// Managing your own passkey mappings requires the FreeIPA self-service
// permission introduced with passkey support in FreeIPA 4.11.
func userAddPasskey(client *ipa.Client, uid, mapping string) error {
	return client.UserAddPasskey(uid, mapping)
}

func userRemovePasskey(client *ipa.Client, uid, mapping string) error {
	return client.UserRemovePasskey(uid, mapping)
}

func userPasskeys(client *ipa.Client, uid string) ([]string, error) {
	u, err := client.UserShow(uid)
	if err != nil {
		return nil, err
	}
	return u.Passkeys, nil
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
		// uncompressed point 0x04 || X || Y. ParsePublicKey has already
		// checked both coordinates are exactly the curve size; this parse
		// rejects points off the curve
		point := append(append([]byte{4}, key.XCoord...), key.YCoord...)
		ec, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return "", err
		}
		pub = ec
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
