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
	"math"
	"math/big"
	"time"

	"github.com/essentialkaos/branca/v2"
	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"
)

type Token struct {
	Username  string        `json:"username"`
	Email     string        `json:"email"`
	First     string        `json:"first,omitempty"`
	Last      string        `json:"last,omitempty"`
	Kind      string        `json:"kind,omitempty"`    // the issuing prefix; empty on tokens issued before it existed
	MaxAge    int64         `json:"max_age,omitempty"` // seconds; overrides email.token_max_age, only with a matching Kind
	Groups    []InviteGroup `json:"groups,omitempty"`
	InvitedBy string        `json:"invited_by,omitempty"`
	Timestamp time.Time     `json:"-"`
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

	claims.Kind = prefix
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

	var tk Token
	err = json.Unmarshal([]byte(brancaToken.Payload()), &tk)
	if err != nil {
		return nil, err
	}

	if tk.Kind != "" && tk.Kind != prefix {
		return nil, errors.New("token of another kind")
	}
	maxAge := viper.GetUint32("email.token_max_age")
	if tk.Kind == prefix && tk.MaxAge > 0 && tk.MaxAge <= math.MaxUint32 {
		maxAge = uint32(tk.MaxAge)
	} else {
		tk.MaxAge = 0
	}
	if brancaToken.IsExpired(maxAge) {
		return nil, errors.New("Token expired")
	}

	tk.Timestamp = brancaToken.Timestamp()

	return &tk, nil
}

var errTokenUsed = errors.New("token already used")

// spendToken marks a parsed token used before its action runs, so two
// concurrent submits cannot both act on it. undo frees the token again for
// an action that failed; undoOnError does that for a handler's error reply.
func (r *Router) spendToken(token, prefix string, claims *Token) (undo func(), err error) {
	key := prefix + TokenUsedPrefix + token
	// one lock per token kind, not per token: lock keys are never freed
	unlock, err := r.lock.holdStrict(prefix + TokenUsedPrefix)
	if err != nil {
		return nil, err
	}
	defer unlock()

	used, err := r.storage.Get(key)
	if err != nil {
		return nil, err
	}
	if used != nil {
		return nil, errTokenUsed
	}

	maxAge := int64(viper.GetInt("email.token_max_age"))
	if claims.MaxAge > 0 {
		maxAge = claims.MaxAge
	}
	ttl := time.Until(claims.Timestamp.Add(time.Duration(maxAge) * time.Second))
	if err := r.storage.Set(key, []byte("true"), ttl); err != nil {
		return nil, err
	}

	return func() {
		if err := r.storage.Delete(key); err != nil {
			slog.Error("Failed to release a single-use link after a failed attempt, it stays spent",
				"username", claims.Username,
				"token_type", prefix,
				"err", err,
			)
		}
	}, nil
}

// undoOnError, deferred after spendToken, gives the token back unless the
// handler answered 200
func undoOnError(c fiber.Ctx, undo func()) {
	if c.Response().StatusCode() != fiber.StatusOK {
		undo()
	}
}

// EnsureSecrets generates server.csrf_secret and email.token_secret when they
// are blank. With redis storage mokey may run as several replicas, which
// must share email.token_secret, so a blank one is an error instead.
func EnsureSecrets() error {
	if viper.GetString("storage.driver") == "redis" && (viper.GetString("server.csrf_secret") == "" || viper.GetString("email.token_secret") == "") {
		return errors.New(`server.csrf_secret and email.token_secret must both be set when storage.driver = "redis": a generated email.token_secret differs per replica and per restart, so reset and invite links mailed by one replica fail on another; set server.csrf_secret as well so no replica generates its own`)
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
