# Go Auth

> [!CAUTION]
> go-auth is now part of the [go-foundation](https://github.com/mirkobrombin/go-foundation) framework. The v1.0.0 release mirrors go-auth v0.2.0, but future versions may introduce breaking changes. Please migrate your project.

A compact **token signing** library for Go services that need lightweight HMAC-backed authentication.

## Features

- **Minimal Token Format:** Signs compact payloads without pulling in a full JWT stack.
- **HMAC-SHA256 Signatures:** Uses a well-known symmetric signing primitive.
- **Small API Surface:** Exposes only payload signing and verification helpers.
- **Service-Friendly:** Great for internal service-to-service or short-lived session tokens.

## Installation

```bash
go get github.com/mirkobrombin/go-auth
```

## Quick Start

```go
package main

import (
    "fmt"
    "time"

    "github.com/mirkobrombin/go-auth/pkg/auth"
)

func main() {
    secret := []byte("super-secret")

    token, err := auth.SignToken(auth.Payload{
        Sub: "service-a",
        Exp: time.Now().Add(5 * time.Minute).Unix(),
    }, secret)
    if err != nil {
        panic(err)
    }

    payload, err := auth.VerifyToken(token, secret)
    if err != nil {
        panic(err)
    }

    fmt.Println(payload.Sub)
}
```

## Documentation

- [Getting Started](docs/getting-started.md)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
