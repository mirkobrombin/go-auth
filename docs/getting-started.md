# Getting Started

`go-auth` provides a deliberately small token format for applications that want signed payloads without a full JWT dependency tree.

## When to use it

Use `go-auth` when you control both sides of the exchange and want a compact HMAC-signed token carrying a subject and expiry timestamp.

## Core types

- `auth.Payload` describes the token body.
- `auth.SignToken` serializes and signs a payload.
- `auth.VerifyToken` validates the signature, decodes the payload, and enforces expiry.

## Notes

- Tokens are base64url encoded and signed with HMAC-SHA256.
- Expiry is checked against `time.Now().Unix()`.
- Keep the shared secret private and rotate it according to your operational requirements.
