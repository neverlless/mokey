package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/stretchr/testify/assert"
)

func TestPasskeyMapping(t *testing.T) {
	assert := assert.New(t)

	// build a COSE EC2 P-256 key like an authenticator would return
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(err)
	// uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes)
	point, err := priv.PublicKey.Bytes()
	assert.NoError(err)

	coseKey := map[int]interface{}{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: point[1:33],
		-3: point[33:65],
	}
	coseBytes, err := webauthncbor.Marshal(coseKey)
	assert.NoError(err)

	credID := []byte("test-credential-id")

	mapping, err := passkeyMapping(credID, coseBytes)
	assert.NoError(err)
	assert.True(strings.HasPrefix(mapping, "passkey:"))

	// both parts must be valid standard base64 (FreeIPA validates this)
	parts := strings.SplitN(strings.TrimPrefix(mapping, "passkey:"), ",", 2)
	assert.Len(parts, 2)
	id, err := base64.StdEncoding.DecodeString(parts[0])
	assert.NoError(err)
	assert.Equal(credID, id)
	spki, err := base64.StdEncoding.DecodeString(parts[1])
	assert.NoError(err)

	// the SPKI carries the authenticator's key, not just any valid encoding
	pub, err := x509.ParsePKIXPublicKey(spki)
	if assert.NoError(err) {
		assert.True(priv.PublicKey.Equal(pub))
	}

	// garbage COSE key must error
	_, err = passkeyMapping(credID, []byte("junk"))
	assert.Error(err)

	// a point off the curve must not be registered
	offCurve := append([]byte{}, point[33:65]...)
	offCurve[31] ^= 1
	coseKey[-3] = offCurve
	coseBytes, err = webauthncbor.Marshal(coseKey)
	assert.NoError(err)
	_, err = passkeyMapping(credID, coseBytes)
	assert.Error(err)
}

func TestPasskeyMappingCurves(t *testing.T) {
	assert := assert.New(t)

	curves := []struct {
		curve elliptic.Curve
		alg   int
		crv   int
	}{
		{elliptic.P256(), -7, 1},
		{elliptic.P384(), -35, 2},
		{elliptic.P521(), -36, 3},
	}
	for _, c := range curves {
		name := c.curve.Params().Name
		priv, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		assert.NoError(err)
		point, err := priv.PublicKey.Bytes()
		assert.NoError(err)
		size := (len(point) - 1) / 2
		x, y := point[1:1+size], point[1+size:]

		cose := func(xc []byte) []byte {
			b, err := webauthncbor.Marshal(map[int]interface{}{
				1: 2, 3: c.alg, -1: c.crv, -2: xc, -3: y,
			})
			assert.NoError(err)
			return b
		}

		mapping, err := passkeyMapping([]byte("id"), cose(x))
		if assert.NoError(err, name) {
			spki, err := base64.StdEncoding.DecodeString(strings.SplitN(mapping, ",", 2)[1])
			assert.NoError(err)
			pub, err := x509.ParsePKIXPublicKey(spki)
			if assert.NoError(err, name) {
				assert.True(priv.PublicKey.Equal(pub), name)
			}
		}

		// COSE requires coordinates of exactly the curve size
		_, err = passkeyMapping([]byte("id"), cose(x[1:]))
		assert.Error(err, name)
		_, err = passkeyMapping([]byte("id"), cose(append([]byte{0}, x...)))
		assert.Error(err, name)
	}
}
