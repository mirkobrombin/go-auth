package auth_test

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/mirkobrombin/go-auth/pkg/auth"
)

func TestSignTokenAndVerifyToken(t *testing.T) {
	secret := []byte("s3cr3t")

	token, err := auth.SignToken(auth.Payload{Sub: "u1", Exp: time.Now().Add(time.Minute).Unix()}, secret)
	if err != nil {
		t.Fatalf("SignToken() error = %v", err)
	}

	payload, err := auth.VerifyToken(token, secret)
	if err != nil {
		t.Fatalf("VerifyToken() error = %v", err)
	}

	if payload.Sub != "u1" {
		t.Fatalf("VerifyToken() subject = %q, want %q", payload.Sub, "u1")
	}
}

func TestVerifyTokenRejectsMalformedToken(t *testing.T) {
	_, err := auth.VerifyToken("invalid", []byte("s3cr3t"))
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("VerifyToken() error = %v, want ErrInvalidToken", err)
	}
}

func TestVerifyTokenRejectsInvalidSignature(t *testing.T) {
	secret := []byte("s3cr3t")

	token, err := auth.SignToken(auth.Payload{Sub: "u1", Exp: time.Now().Add(time.Minute).Unix()}, secret)
	if err != nil {
		t.Fatalf("SignToken() error = %v", err)
	}

	payload, signature, ok := splitToken(token)
	if !ok {
		t.Fatalf("splitToken() = false, want true")
	}
	tampered := payload + "." + base64.RawURLEncoding.EncodeToString([]byte(signature+"tampered"))

	_, err = auth.VerifyToken(tampered, secret)
	if !errors.Is(err, auth.ErrInvalidSignature) {
		t.Fatalf("VerifyToken() error = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyTokenRejectsExpiredToken(t *testing.T) {
	secret := []byte("s3cr3t")

	token, err := auth.SignToken(auth.Payload{Sub: "u1", Exp: time.Now().Add(-time.Minute).Unix()}, secret)
	if err != nil {
		t.Fatalf("SignToken() error = %v", err)
	}

	_, err = auth.VerifyToken(token, secret)
	if !errors.Is(err, auth.ErrExpiredToken) {
		t.Fatalf("VerifyToken() error = %v, want ErrExpiredToken", err)
	}
}

func splitToken(token string) (string, string, bool) {
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			return token[:i], token[i+1:], true
		}
	}
	return "", "", false
}
