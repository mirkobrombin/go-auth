package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

var (
	// ErrInvalidToken indicates that the token does not have the expected wire format.
	ErrInvalidToken = errors.New("auth: invalid token")
	// ErrInvalidSignature indicates that the token signature does not match the payload.
	ErrInvalidSignature = errors.New("auth: invalid signature")
	// ErrExpiredToken indicates that the token has already expired.
	ErrExpiredToken = errors.New("auth: token expired")
)

// Payload is the signed token payload.
type Payload struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

// SignToken serializes and signs the provided payload with HMAC-SHA256.
func SignToken(p Payload, secret []byte) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}

	sig := computeSig(b, secret)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyToken validates the token signature, decodes the payload, and enforces expiry.
func VerifyToken(token string, secret []byte) (Payload, error) {
	idx := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Payload{}, ErrInvalidToken
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(token[:idx])
	if err != nil {
		return Payload{}, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(token[idx+1:])
	if err != nil {
		return Payload{}, err
	}

	expected := computeSig(payloadBytes, secret)
	if !hmac.Equal(signature, expected) {
		return Payload{}, ErrInvalidSignature
	}

	var payload Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return Payload{}, err
	}

	if time.Now().Unix() > payload.Exp {
		return Payload{}, ErrExpiredToken
	}

	return payload, nil
}

func computeSig(payload, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write(payload)
	return h.Sum(nil)
}
