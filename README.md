# Seal

Seal is a compact JWT/JWS signing, verification, and decode library for ESP32.

Seal helps Arduino ESP32 projects create and validate HS256 JSON Web Tokens with caller-configurable size limits, bounded dynamic allocations, result-based errors, async APIs, and an internal crypto backend boundary.

[![CI](https://github.com/ZekStack/seal/actions/workflows/ci.yml/badge.svg)](https://github.com/ZekStack/seal/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ZekStack/seal?sort=semver)](https://github.com/ZekStack/seal/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

## Why use Seal?

* **JWT-focused** - sign, verify, and decode compact JWTs.
* **ESP32-friendly** - bounded token, payload, queue, and stack configuration.
* **Familiar API** - shaped after the useful parts of Node.js `jsonwebtoken`.
* **Thread-safe** - public methods are guarded by FreeRTOS mutexes when enabled.
* **Backend-isolated crypto** - v0.1 uses mbedTLS behind `SealCrypto.h` so the implementation can switch later.

## Install

### PlatformIO

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino

lib_deps =
  https://github.com/ZekStack/seal.git
  bblanchon/ArduinoJson@>=7.0.0
```

### Arduino IDE

This library is not published to Arduino Library Manager yet.

Install it by downloading the repository ZIP or cloning it into your Arduino libraries folder.

```txt
Arduino/libraries/Seal
```

## Quick Start

```cpp
#include <Arduino.h>
#include <ArduinoJson.h>
#include <Seal.h>

Seal seal;

void setup() {
	Serial.begin(115200);
	seal.init();

	JsonDocument payload;
	payload["deviceId"] = "panel-01";

	SealToken token;
	SealResult result = seal.sign(payload, "super-secret", token);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	Serial.println(token.c_str());

	JsonDocument verified;
	result = seal.verify(token.c_str(), "super-secret", verified);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	Serial.println(verified["deviceId"].as<const char *>());
}

void loop() {
	delay(1000);
}
```

## Important Notes

> [!IMPORTANT]
> `decode()` does not verify a token. Never trust decoded data from external input unless `verify()` succeeds.

JWT payloads are signed, not encrypted. Anyone who has the token can read its header and payload.

HS256 uses the same shared secret for signing and verification. Weak secrets make tokens forgeable.

When `addIssuedAtByDefault` is enabled and no clock provider or fixed clock is available, Seal signs without adding `iat`.

Verification requires `alg: "HS256"` and ignores `typ` by default for interoperability. Seal accepts unpadded JWT base64url and leniently accepts trailing `=` padding.

## Examples

| Example             | Description                                      |
| ------------------- | ------------------------------------------------ |
| `basic-sign`        | Sign a minimal payload.                          |
| `basic-verify`      | Sign and verify a token.                         |
| `decode-token`      | Decode untrusted payload data without verifying. |
| `tempo-expiration`  | Use epoch timestamps from an external clock.     |
| `async-sign-verify` | Use callback-based async sign and verify.        |
| `caller-buffer`     | Sign into a caller-owned output buffer.          |

Start with:

```txt
examples/basic-sign
```

## Documentation

| Document                  | Description                                |
| ------------------------- | ------------------------------------------ |
| `docs/getting-started.md` | Step-by-step setup guide.                  |
| `docs/configuration.md`   | Available configuration options.           |
| `docs/api.md`             | Public classes, methods, and result types. |
| `docs/examples.md`        | Explanation of all examples.               |
| `docs/security.md`        | JWT and HS256 security notes.              |
| `docs/memory.md`          | Token, payload, async, and PSRAM behavior. |
| `docs/troubleshooting.md` | Common issues and solutions.               |

## API Overview

```cpp
SealResult init(const SealConfig& config = SealConfig());
SealResult sign(const JsonDocument& payload, const SealOptions& options, const char* secret, SealToken& outToken);
SealResult verify(const char* token, const char* secret, const SealVerifyOptions& options, JsonDocument& outPayload);
SealResult decode(const char* token, JsonDocument& outPayload);
```

For the full API, see [`docs/api.md`](docs/api.md).

## Compatibility

| Item         | Support                    |
| ------------ | -------------------------- |
| Framework    | Arduino ESP32              |
| Platform     | `espressif32`              |
| Language     | C++20                      |
| Algorithms   | HS256                      |
| Dependencies | ArduinoJson v7, mbedTLS    |
| Exceptions   | Not used                   |
| Status       | Experimental               |

## jsonwebtoken Compatibility

| Feature                 | Seal v0.1 |
| ----------------------- | --------- |
| `sign()` sync           | Yes       |
| `sign()` callback       | Yes       |
| `verify()` sync         | Yes       |
| `verify()` callback     | Yes       |
| `decode()`              | Yes       |
| HS256                   | Yes       |
| `iat`, `exp`, `nbf`     | Yes       |
| `issuer`, `subject`     | Yes       |
| `audience`, string only | Yes       |
| `jwtid`, `keyid`        | Yes       |
| String durations        | No        |
| RS256 / ES256           | No        |

## License

MIT - see [`LICENSE.md`](LICENSE.md).

## ZekStack

Part of the ZekStack ESP32 library stack.
