package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
}

func TestRedisTLSConfig(t *testing.T) {
	t.Cleanup(viper.Reset)
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	ca := filepath.Join(dir, "ca.pem")
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	garbage := filepath.Join(dir, "garbage.pem")
	writePEM(t, ca, "CERTIFICATE", der)
	writePEM(t, certFile, "CERTIFICATE", der)
	writePEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	require.NoError(t, os.WriteFile(garbage, []byte("not a cert"), 0o600))

	set := func(ca, cert, key string) {
		viper.Set("storage.redis.ca_file", ca)
		viper.Set("storage.redis.cert_file", cert)
		viper.Set("storage.redis.key_file", key)
	}

	set("", "", "")
	cfg, err := redisTLSConfig("rediss://redis.example.org:6379/0")
	assert.NoError(t, err)
	assert.Nil(t, cfg, "URL scheme decides")

	set(ca, "", "")
	cfg, err = redisTLSConfig("redis://redis.example.org:6379/0")
	require.NoError(t, err)
	assert.Equal(t, "redis.example.org", cfg.ServerName, "a CA turns TLS on for redis://")
	assert.NotNil(t, cfg.RootCAs)

	set(ca, certFile, keyFile)
	cfg, err = redisTLSConfig("rediss://redis.example.org:6379/0?skip_verify=true")
	require.NoError(t, err)
	assert.Len(t, cfg.Certificates, 1)
	assert.True(t, cfg.InsecureSkipVerify, "URL options kept")

	for name, files := range map[string][3]string{
		"cert without key": {"", certFile, ""},
		"missing ca":       {filepath.Join(dir, "nope.pem"), "", ""},
		"garbage ca":       {garbage, "", ""},
		"garbage cert":     {"", garbage, keyFile},
	} {
		set(files[0], files[1], files[2])
		_, err := redisTLSConfig("rediss://redis.example.org:6379/0")
		assert.Error(t, err, name)
	}
}
