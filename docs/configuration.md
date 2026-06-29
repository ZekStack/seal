# Configuration

`SealConfig` controls memory limits, async behavior, and task settings.

```cpp
SealConfig config;
config.maxTokenSize = 4096;
config.maxPayloadSize = 2048;
config.queueSize = 8;
config.enableAsync = true;
config.preferPsram = true;

seal.init(config);
```

## Size Limits

| Field              | Default | Meaning                         |
| ------------------ | ------- | ------------------------------- |
| `maxTokenSize`     | 4096    | Maximum compact JWT length.     |
| `maxPayloadSize`   | 2048    | Maximum serialized payload JSON. |
| `maxHeaderSize`    | 512     | Maximum serialized header JSON. |
| `maxSignatureSize` | 64      | Maximum encoded signature text. |

## Async Settings

| Field            | Default           | Meaning                         |
| ---------------- | ----------------- | ------------------------------- |
| `enableAsync`    | `true`            | Create the async worker task.   |
| `queueSize`      | 8                 | Maximum queued async jobs.      |
| `stackSizeBytes` | 4096              | Worker task stack size in bytes. |
| `priority`       | 1                 | Worker task priority.           |
| `coreId`         | `tskNO_AFFINITY`  | Worker task core affinity.      |
| `stackType`      | `Auto`            | Internal or PSRAM stack choice. |

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
