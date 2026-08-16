package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionInvalidatedByPasswordChange(t *testing.T) {
	assert := assert.New(t)

	// no marker — session valid
	assert.False(sessionInvalidatedByPasswordChange(100, nil))
	// garbage marker — fail open (treated as no marker)
	assert.False(sessionInvalidatedByPasswordChange(100, []byte("junk")))
	// login before change — invalid
	assert.True(sessionInvalidatedByPasswordChange(99, []byte("100")))
	// missing login_time (zero value) — invalid
	assert.True(sessionInvalidatedByPasswordChange(0, []byte("100")))
	// same second — survives
	assert.False(sessionInvalidatedByPasswordChange(100, []byte("100")))
	// login after change — valid
	assert.False(sessionInvalidatedByPasswordChange(101, []byte("100")))
}
