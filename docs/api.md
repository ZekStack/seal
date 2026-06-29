# API

Seal exposes a small result-based API through `<Seal.h>`.

## Core Types

`SealResult` contains a `SealCode` and message. It converts to `true` only when the code is `SealCode::Ok`.

`SealToken` owns generated token memory and is move-only.

`SealOptions` controls signing claims: `iat`, `exp`, `nbf`, `issuer`, `subject`, `audience`, `jwtid`, and `keyid`.

`SealVerifyOptions` controls expected claims, expiration behavior, clock tolerance, explicit clock timestamp, and `maxAgeSeconds`.

## Signing

```cpp
SealResult sign(const JsonDocument& payload, const char* secret, SealToken& outToken);
SealResult sign(const JsonDocument& payload, const SealOptions& options, const char* secret, SealToken& outToken);
SealResult sign(const JsonDocument& payload, const SealOptions& options, const char* secret, char* outToken, size_t outTokenSize, size_t& written);
```

Signing produces compact JWT serialization:

```txt
base64url(header).base64url(payload).base64url(signature)
```

## Verification

```cpp
SealResult verify(const char* token, const char* secret, JsonDocument& outPayload);
SealResult verify(const char* token, const char* secret, const SealVerifyOptions& options, JsonDocument& outPayload);
```

Verification requires exactly three token segments, `alg` equal to `HS256`, a non-empty signature, valid JSON, a matching HMAC-SHA256 signature, and matching configured claims.

## Decode

```cpp
SealResult decode(const char* token, JsonDocument& outPayload);
SealResult decodeHeader(const char* token, JsonDocument& outHeader);
SealResult decodeComplete(const char* token, JsonDocument& outHeader, JsonDocument& outPayload);
```

Decode parses token data but does not verify trust.

## Async

```cpp
SealResult sign(const JsonDocument& payload, const char* secret, SealSignCallback callback);
SealResult verify(const char* token, const char* secret, SealVerifyCallback callback);
SealResult decode(const char* token, SealDecodeCallback callback);
```

Async callbacks run from Seal's worker task. The `JsonDocument&` passed to verify and decode callbacks is valid only during the callback.

## Crypto Backend

Seal v0.1 uses mbedTLS for production HMAC-SHA256. Backend-specific headers are isolated in `src/internal/SealCryptoMbedTls.cpp`; signing and verification code call only the internal `SealCrypto.h` facade. This is an internal extension point, not a public runtime plugin API.
