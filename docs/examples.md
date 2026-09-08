# Examples

## `basic-sign`

Creates a JSON payload and signs it with HS256.

## `basic-verify`

Signs a token, verifies it, and reads the verified payload.

## `decode-token`

Shows unsafe decode. This is useful for inspecting token contents, not for authorization.

## `tempo-expiration`

Shows how to pass epoch timestamps from an external clock source. Seal does not include or depend on Tempo.

## `async-sign-verify`

Queues signing and verification work on Seal's Strata-backed worker task.

## `caller-buffer`

Signs into a fixed caller-owned character buffer. Caller-owned storage is not affected by `SealConfig::memory`.

## `memory-policy`

Shows the shared ZekStack memory policy. The example prefers external RAM for Seal-owned buffers while forcing the async worker stack into internal RAM.

```cpp
SealConfig config;
config.memory.allocation = Strata::Placement::PreferExternal;
config.memory.taskStack = Strata::Placement::Internal;
seal.init(config);
```
