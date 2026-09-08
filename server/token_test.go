// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"errors"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/gofiber/storage/memory/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	secret, _ := GenerateSecret(32)
	viper.Set("email.token_secret", secret)
	viper.Set("email.token_max_age", uint32(3))
	// reissue is gated by the resend cooldown now, not the token lifetime
	viper.Set("email.resend_cooldown", 3)
	defer viper.Set("email.resend_cooldown", 180)

	assert := assert.New(t)

	email := "user@example.com"
	uid := "user"

	storage := memory.New()

	token, err := NewToken(uid, email, TokenPasswordReset, storage)
	if assert.NoError(err) {
		assert.Greater(len(token), 0)
	}

	claims, err := ParseToken(token, TokenPasswordReset, storage)
	if assert.NoError(err) {
		assert.Equal(claims.Username, uid)
		assert.Equal(claims.Email, email)
	}

	// Should error token already issued
	_, err = NewToken(uid, email, TokenPasswordReset, storage)
	assert.Error(err)

	time.Sleep(time.Second * 4)

	viper.Set("email.token_max_age", uint32(1))

	expToken, err := NewToken(uid, email, TokenPasswordReset, storage)
	if assert.NoError(err) {
		assert.Greater(len(token), 0)
	}

	time.Sleep(time.Second * 3)

	_, err = ParseToken(expToken, TokenPasswordReset, storage)
	assert.Error(err)
}

// failingStorage errors on Get — simulates an unhealthy storage backend
type failingStorage struct{ fiber.Storage }

func (s *failingStorage) Get(key string) ([]byte, error) {
	return nil, errors.New("storage backend down")
}

func TestTokenFailsClosedOnStorageError(t *testing.T) {
	assert := assert.New(t)

	secret, _ := GenerateSecret(32)
	viper.Set("email.token_secret", secret)
	viper.Set("email.token_max_age", uint32(3600))

	healthy := memory.New()
	token, err := NewToken("walter", "walter@example.com", TokenPasswordReset, healthy)
	assert.NoError(err)

	broken := &failingStorage{healthy}

	// an unparseable used-marker must reject the token, not accept it
	_, err = ParseToken(token, TokenPasswordReset, broken)
	assert.Error(err)

	// issuance must also fail closed
	_, err = NewToken("jesse", "jesse@example.com", TokenPasswordReset, broken)
	assert.Error(err)
}

// #17: the issued marker used to live as long as the token itself, so a
// verification email lost in transit could not be resent for a full hour
func TestTokenResendCooldown(t *testing.T) {
	assert := assert.New(t)

	secret, _ := GenerateSecret(32)
	viper.Set("email.token_secret", secret)
	viper.Set("email.token_max_age", uint32(3600))
	viper.Set("email.resend_cooldown", 1)
	defer viper.Set("email.resend_cooldown", 180)

	storage := memory.New()

	_, err := NewToken("walter", "walter@example.com", TokenAccountVerify, storage)
	assert.NoError(err)

	// still inside the cooldown
	_, err = NewToken("walter", "walter@example.com", TokenAccountVerify, storage)
	assert.EqualError(err, "token already issued")

	time.Sleep(1500 * time.Millisecond)

	// cooldown elapsed: a resend is allowed even though the first token
	// has not expired yet
	second, err := NewToken("walter", "walter@example.com", TokenAccountVerify, storage)
	if assert.NoError(err) {
		assert.NotEmpty(second)
	}
}
