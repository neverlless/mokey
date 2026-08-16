package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	coseKey := map[int]interface{}{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: priv.PublicKey.X.Bytes(),
		-3: priv.PublicKey.Y.Bytes(),
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
	_, err = base64.StdEncoding.DecodeString(parts[1])
	assert.NoError(err)

	// garbage COSE key must error
	_, err = passkeyMapping(credID, []byte("junk"))
	assert.Error(err)
}
