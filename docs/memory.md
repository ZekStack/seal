# Memory

Seal enforces configured size limits before accepting or producing tokens. Internally, Seal uses bounded dynamic allocations for serialization, token building, decoded segments, and queued async jobs.

## Defaults

| Limit              | Default |
| ------------------ | ------- |
| Full token         | 4096    |
| Serialized payload | 2048    |
| Serialized header  | 512     |
| Signature text     | 64      |
| Async queue jobs   | 8       |

## `SealToken`

`SealToken` owns generated token memory. It is move-only and clears memory when destroyed or reset.

For deterministic output storage, use the caller-provided buffer overload:

```cpp
char token[512];
size_t written = 0;
seal.sign(payload, options, secret, token, sizeof(token), written);
```

## Async Jobs

Async calls copy the serialized payload, token string, secret, options, and callback before returning. If the configured limits are exceeded, submission fails immediately.

During `deinit()`, queued async jobs that have not started may be securely discarded without invoking callbacks. Copied secrets and token buffers are cleared before those jobs are released.

## PSRAM

When `preferPsram` is enabled, Seal prefers PSRAM for owned token memory and may use a PSRAM stack for the async worker when supported by the ESP32 core.
