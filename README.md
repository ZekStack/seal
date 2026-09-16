# Seal

Seal is a compact JWT/JWS signing, verification, and decode library for ESP32.

Seal helps Arduino ESP32 projects create and validate HS256 JSON Web Tokens with caller-configurable size limits, Strata-backed memory placement, result-based errors, async APIs, and an internal crypto backend boundary.

[![CI](https://github.com/ZekStack/seal/actions/workflows/ci.yml/badge.svg)](https://github.com/ZekStack/seal/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ZekStack/seal?sort=semver)](https://github.com/ZekStack/seal/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

## Why use Seal?

* **JWT-focused** - sign, verify, and decode compact JWTs.
* **ESP32-friendly** - bounded token, payload, queue, and stack configuration.
* **Strata-backed memory policy** - independently choose placement for Seal-owned allocations and the async task stack.
* **Familiar API** - shaped after the useful parts of Node.js `jsonwebtoken`.
* **Thread-safe** - public methods are guarded by a Strata-backed FreeRTOS recursive mutex when enabled.
* **Backend-isolated crypto** - mbedTLS stays behind `SealCrypto.h` so the implementation can switch later.

## Install

Seal v0.2.0 requires Strata v0.1.2 and ArduinoJson 7.

### PlatformIO

```ini
[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino

lib_deps =
  https://github.com/ZekStack/seal.git
  https://github.com/ZekStack/strata.git#v0.1.2
  bblanchon/ArduinoJson@>=7.0.0
```

### Arduino IDE

This library is not published to Arduino Library Manager yet.

Install Seal, Strata v0.1.2, and ArduinoJson 7 into your Arduino libraries folder.

```txt
Arduino/libraries/Seal
Arduino/libraries/Strata
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

## Memory Policy

Seal uses the same `Strata::MemoryPolicy` contract as other migrated ZekStack libraries.

```cpp
SealConfig config;
config.memory.allocation = Strata::Placement::PreferExternal;
config.memory.taskStack = Strata::Placement::PreferExternal;
seal.init(config);
```

The defaults are `PreferExternal` for both fields to preserve Seal v0.1's PSRAM-preferred behavior.

`memory.allocation` controls Seal-owned token buffers, temporary strings/vectors, async jobs and their copied data, internal ArduinoJson storage, and async queue item storage.

`memory.taskStack` controls the async worker stack.

FreeRTOS control blocks for the queue, task, recursive mutex, and shutdown semaphore remain internal through Strata. Caller-provided output buffers and caller-provided `JsonDocument` instances remain caller-owned.

Use `Strata::Placement::RequireExternal` when lack of PSRAM must be treated as an error, or `Strata::Placement::Internal` when a resource must stay in internal RAM.

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
| `memory-policy`     | Configure Strata allocation and task placement.  |

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
| `docs/memory.md`          | Strata ownership and placement behavior.   |
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

| Item         | Support                         |
| ------------ | ------------------------------- |
| Framework    | Arduino ESP32                   |
| Platform     | `espressif32`                   |
| Language     | C++20                           |
| Algorithms   | HS256                           |
| Dependencies | ArduinoJson v7, Strata v0.1.2, mbedTLS |
| Exceptions   | Not used by Seal production code |
| Status       | Early-stage `0.2.0`             |

## jsonwebtoken Compatibility

| Feature                 | Seal v0.2 |
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

## v0.1.0 to v0.2.0

Seal v0.2.0 removes `SealStackType` and `SealConfig::preferPsram`. Configure memory through `SealConfig::memory` instead. See [`docs/configuration.md`](docs/configuration.md) for the migration table.

## License

MIT - see [`LICENSE.md`](LICENSE.md).

## ZekStack

Part of the ZekStack ESP32 library stack.
