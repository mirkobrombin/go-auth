package main

import (
	"fmt"
	"time"

	"github.com/mirkobrombin/go-auth/pkg/auth"
)

func main() {
	secret := []byte("demo-secret")

	token, err := auth.SignToken(auth.Payload{
		Sub: "example-user",
		Exp: time.Now().Add(2 * time.Minute).Unix(),
	}, secret)
	if err != nil {
		panic(err)
	}

	payload, err := auth.VerifyToken(token, secret)
	if err != nil {
		panic(err)
	}

	fmt.Printf("verified subject: %s\n", payload.Sub)
}
