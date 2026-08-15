package server

import (
	"crypto/tls"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestTLSVersionFromConfig(t *testing.T) {
	assert := assert.New(t)
	defer viper.Reset()

	viper.Set("server.tls_min_version", "")
	v, err := tlsVersionFromConfig()
	assert.NoError(err)
	assert.Equal(uint16(tls.VersionTLS12), v)

	viper.Set("server.tls_min_version", "1.3")
	v, err = tlsVersionFromConfig()
	assert.NoError(err)
	assert.Equal(uint16(tls.VersionTLS13), v)

	viper.Set("server.tls_min_version", "1.0")
	_, err = tlsVersionFromConfig()
	assert.Error(err)
}

func TestCipherSuitesFromConfig(t *testing.T) {
	assert := assert.New(t)
	defer viper.Reset()

	viper.Set("server.tls_ciphers", []string{})
	ids, err := cipherSuitesFromConfig()
	assert.NoError(err)
	assert.Nil(ids)

	viper.Set("server.tls_ciphers", []string{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	})
	ids, err = cipherSuitesFromConfig()
	assert.NoError(err)
	assert.Equal([]uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}, ids)

	viper.Set("server.tls_ciphers", []string{"NOT_A_CIPHER"})
	_, err = cipherSuitesFromConfig()
	assert.Error(err)
}
