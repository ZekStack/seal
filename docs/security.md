# Security

Seal v0.1 is a JWT/JWS library, not an encryption library.

JWT headers and payloads are base64url encoded, not encrypted. Anyone holding a token can decode and read its claims.

## Verification Is Mandatory

`decode()` does not verify signatures. Use `verify()` before trusting any value from a token.

## HS256 Secrets

HS256 uses one shared secret for signing and verification. If the secret is weak, leaked, or extracted, attackers can forge valid tokens.

Use high-entropy secrets and rotate them when compromise is possible.

## Embedded Secret Risk

Secrets stored in firmware can be extracted when physical compromise is in scope. Seal can validate token integrity, but it cannot protect a secret that is available to an attacker through device extraction.

## Expiration Requires Time

`exp`, `nbf`, and `maxAgeSeconds` validation require a valid epoch clock. If time is required and unavailable, Seal returns `SealCode::ClockUnavailable`.

## Crypto Backend Boundary

Production v0.1 crypto uses mbedTLS behind `SealCrypto.h`. This boundary exists so the backend can be replaced later without changing the public Seal API.
