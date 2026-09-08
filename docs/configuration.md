# Configuration

`SealConfig` controls memory placement, size limits, async behavior, and task settings.

```cpp
SealConfig config;
config.memory.allocation = Strata::Placement::PreferExternal;
config.memory.taskStack = Strata::Placement::PreferExternal;
config.maxTokenSize = 4096;
config.maxPayloadSize = 2048;
config.queueSize = 8;
config.enableAsync = true;

seal.init(config);
```

## Memory policy

Seal uses the shared ZekStack `Strata::MemoryPolicy` contract.

| Field | Default | Meaning |
| --- | --- | --- |
| `memory.allocation` | `Strata::Placement::PreferExternal` | Placement for movable Seal-owned allocations such as tokens, temporary strings/vectors, async jobs, internal ArduinoJson storage, and async queue item storage. |
| `memory.taskStack` | `Strata::Placement::PreferExternal` | Placement for the async worker task stack. |

`PreferExternal` uses external RAM when available and falls back to internal memory. `RequireExternal` fails when external memory cannot satisfy the request. `Internal` forces internal RAM. `Default` uses the Strata backend default.

FreeRTOS control blocks for the mutex, queue, binary shutdown semaphore, and task stay in internal memory through Strata regardless of these settings. Caller-provided `JsonDocument` instances and caller-provided output buffers remain caller-owned and do not inherit Seal's policy.

## Size Limits

| Field              | Default | Meaning                          |
| ------------------ | ------- | -------------------------------- |
| `maxTokenSize`     | 4096    | Maximum compact JWT length.      |
| `maxPayloadSize`   | 2048    | Maximum serialized payload JSON. |
| `maxHeaderSize`    | 512     | Maximum serialized header JSON.  |
| `maxSignatureSize` | 64      | Maximum encoded signature text.  |

## Async Settings

| Field            | Default          | Meaning                          |
| ---------------- | ---------------- | -------------------------------- |
| `enableAsync`    | `true`           | Create the async worker task.    |
| `queueSize`      | 8                | Maximum queued async jobs.       |
| `stackSizeBytes` | 4096             | Worker task stack size in bytes. |
| `priority`       | 1                | Worker task priority.            |
| `coreId`         | `tskNO_AFFINITY` | Worker task core affinity.       |
| `useMutex`       | `true`           | Guard Seal state with a recursive mutex. |

## Time

Seal accepts a bindable time provider:

```cpp
seal.setTimeProvider([](uint64_t& epochSeconds) {
	epochSeconds = currentEpochSeconds();
	return true;
});
```

For deterministic tests:

```cpp
seal.setClockTimestamp(1710000000);
seal.clearClockTimestamp();
```

When `SealConfig::addIssuedAtByDefault` is true, `sign()` adds `iat` only if a fixed clock or time provider returns an epoch timestamp. If no clock is available, signing still succeeds and `iat` is silently omitted.

## Migration from v0.1.0

Seal v0.2.0 removes the Seal-specific stack/PSRAM vocabulary in favor of Strata.

| v0.1.0 | v0.2.0 |
| --- | --- |
| `SealStackType::Auto` with `preferPsram = true` | `memory.taskStack = Strata::Placement::PreferExternal` |
| `SealStackType::Auto` with `preferPsram = false` | `memory.taskStack = Strata::Placement::Internal` |
| `SealStackType::Internal` | `memory.taskStack = Strata::Placement::Internal` |
| `SealStackType::Psram` | `memory.taskStack = Strata::Placement::RequireExternal` |
| `preferPsram = true` for Seal-owned buffers | `memory.allocation = Strata::Placement::PreferExternal` |
| `preferPsram = false` for Seal-owned buffers | `memory.allocation = Strata::Placement::Internal` |

`SealStackType` and `preferPsram` are intentionally removed rather than kept as aliases so Seal uses the same memory-policy vocabulary as the rest of ZekStack.
