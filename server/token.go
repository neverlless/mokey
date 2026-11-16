// Copyright 2015 mokey Authors. All rights reserved.
// Use of this source code is governed by a BSD style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"time"

	"github.com/essentialkaos/branca/v2"
	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

type Token struct {
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	First     string    `json:"first,omitempty"`
	Last      string    `json:"last,omitempty"`
	Timestamp time.Time `json:"-"`
}

func GenerateSecret(n int) (string, error) {
	secret := make([]byte, n)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(secret), nil
}

func GenerateSecretString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-!@#$%^&*(){}[]"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

func NewToken(username, email, prefix string, storage fiber.Storage) (string, error) {
	return issueToken(username, &Token{Username: username, Email: email}, prefix, storage)
}

// issueToken guards re-issue by marker; claims.Username may differ from it
// (an invite is keyed by email but can carry a preset username).
func issueToken(marker string, claims *Token, prefix string, storage fiber.Storage) (string, error) {
	// A storage error means we can't prove no token is outstanding — fail
	// closed, don't issue another one
	tokenIssued, err := storage.Get(prefix + TokenIssuedPrefix + marker)
	if err != nil {
		return "", err
	}
	if tokenIssued != nil {
		return "", errors.New("token already issued")
	}

	jsonBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	key, err := hex.DecodeString(viper.GetString("email.token_secret"))
	if err != nil {
		return "", err
	}

	b, err := branca.NewBranca(key)
	if err != nil {
		return "", err
	}

	token, err := b.EncodeToString(jsonBytes)
	if err != nil {
		return "", err
	}

	// The marker expires after the resend cooldown, not after the token
	// itself: an email lost in transit must be requestable again within
	// minutes rather than after the token's full lifetime (ubccr/mokey#17).
	// Links issued earlier stay valid until they expire; each is single-use
	// and every one of them goes to the same registered address.
	if err := storage.Set(prefix+TokenIssuedPrefix+marker, []byte("true"), time.Duration(viper.GetInt("email.resend_cooldown"))*time.Second); err != nil {
		return "", err
	}

	return token, nil
}

func ParseToken(token, prefix string, storage fiber.Storage) (*Token, error) {
	// A storage error means we can't prove the token is unused — fail
	// closed, treat it as spent (single-use enforcement must not silently
	// disappear when the storage backend is unhealthy)
	tokenUsed, err := storage.Get(prefix + TokenUsedPrefix + token)
	if err != nil {
		return nil, err
	}
	if tokenUsed != nil {
		return nil, errors.New("token already used")
	}

	key, err := hex.DecodeString(viper.GetString("email.token_secret"))
	if err != nil {
		return nil, err
	}

	b, err := branca.NewBranca(key)
	if err != nil {
		return nil, err
	}

	brancaToken, err := b.DecodeString(token)
	if err != nil {
		return nil, err
	}

	if brancaToken.IsExpired(viper.GetUint32("email.token_max_age")) {
		return nil, errors.New("Token expired")
	}

	var tk Token
	err = json.Unmarshal([]byte(brancaToken.Payload()), &tk)
	if err != nil {
		return nil, err
	}

	tk.Timestamp = brancaToken.Timestamp()

	return &tk, nil
}

// MarkTokenUsed runs after the token's action has taken effect, so a storage
// failure cannot be rolled back: it is logged, and the token stays valid until
// it expires
func MarkTokenUsed(token, prefix string, claims *Token, storage fiber.Storage) {
	ttl := time.Until(claims.Timestamp.Add(time.Duration(viper.GetInt("email.token_max_age")) * time.Second))
	if err := storage.Set(prefix+TokenUsedPrefix+token, []byte("true"), ttl); err != nil {
		slog.Error("Failed to mark token used",
			"username", claims.Username,
			"token_type", prefix,
			"err", err,
		)
	}
}

// EnsureSecrets generates server.csrf_secret and email.token_secret when they
// are blank. With redis storage mokey may run as several replicas, which
// must share both, so a missing one is an error instead.
func EnsureSecrets() error {
	if viper.GetString("storage.driver") == "redis" && (viper.GetString("server.csrf_secret") == "" || viper.GetString("email.token_secret") == "") {
		return errors.New(`server.csrf_secret and email.token_secret must both be set when storage.driver = "redis": every replica needs the same secrets, or CSRF tokens and links in emails sent by one replica fail on another and stop working after a restart`)
	}

	generated := []string{}
	if viper.GetString("email.token_secret") == "" {
		secret, err := GenerateSecret(32)
		if err != nil {
			return err
		}
		viper.Set("email.token_secret", secret)
		generated = append(generated, "email.token_secret")
	}
	if viper.GetString("server.csrf_secret") == "" {
		secret, err := GenerateSecretString(16)
		if err != nil {
			return err
		}
		viper.Set("server.csrf_secret", secret)
		generated = append(generated, "server.csrf_secret")
	}
	if len(generated) > 0 {
		slog.Warn("Generated random secrets for this run; links in sent emails stop working after a restart. Set them in the config to keep them valid",
			"keys", generated,
		)
	}
	return nil
}
