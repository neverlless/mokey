package server

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnsureSecrets(t *testing.T) {
	t.Cleanup(viper.Reset)

	for _, set := range []string{"", "server.csrf_secret", "email.token_secret"} {
		viper.Reset()
		viper.Set("storage.driver", "redis")
		if set != "" {
			viper.Set(set, "test-secret-placeholder")
		}
		err := EnsureSecrets()
		require.Error(t, err, "redis with %q set", set)
		assert.Contains(t, err.Error(), "server.csrf_secret")
		assert.Contains(t, err.Error(), "email.token_secret")
		assert.Contains(t, err.Error(), "replica")
	}

	viper.Reset()
	viper.Set("storage.driver", "redis")
	viper.Set("server.csrf_secret", "test-secret-placeholder")
	viper.Set("email.token_secret", strings.Repeat("ab", 32))
	require.NoError(t, EnsureSecrets())
	assert.Equal(t, "test-secret-placeholder", viper.GetString("server.csrf_secret"))

	// mokey.toml.sample ships both keys blank
	viper.Reset()
	viper.Set("storage.driver", "redis")
	viper.Set("server.csrf_secret", "")
	viper.Set("email.token_secret", "")
	require.Error(t, EnsureSecrets(), "blank counts as unset")

	for _, driver := range []string{"memory", "sqlite3"} {
		viper.Reset()
		viper.Set("storage.driver", driver)
		viper.Set("server.csrf_secret", "")
		require.NoError(t, EnsureSecrets())
		assert.Len(t, viper.GetString("email.token_secret"), 64, "32 random bytes, hex")
		assert.NotEmpty(t, viper.GetString("server.csrf_secret"))
	}
}
