# Memory

Seal v0.2.0 routes Seal-owned allocations through Strata v0.1.2. The caller chooses placement through `SealConfig::memory`, while safety-critical FreeRTOS metadata remains internal.

## Defaults

```cpp
SealConfig config;
config.memory.allocation = Strata::Placement::PreferExternal;
config.memory.taskStack = Strata::Placement::PreferExternal;
```

These defaults preserve Seal v0.1.0's preference for PSRAM while gaining explicit fallback and failure semantics from Strata.

| Limit              | Default |
| ------------------ | ------- |
| Full token         | 4096    |
| Serialized payload | 2048    |
| Serialized header  | 512     |
| Signature text     | 64      |
| Async queue jobs   | 8       |

## Ownership and placement

| Resource | Placement / owner |
| --- | --- |
| `SealImpl` control state | Internal Strata allocation |
| `SealToken` memory | `memory.allocation` |
| serialization/base64 temporary storage | `memory.allocation` |
| internal strings and vectors | `memory.allocation` |
| async `SealJob` objects | `memory.allocation` |
| async payload/token/secret copies | `memory.allocation` |
| internal ArduinoJson documents | `memory.allocation` |
| async queue item storage | `memory.allocation` |
| queue control block | Internal through Strata |
| recursive mutex control block | Internal through Strata |
| shutdown binary semaphore control block | Internal through Strata |
| async worker stack | `memory.taskStack` |
| task control block | Internal through Strata |
| caller-provided output buffer | Caller-owned |
| caller-provided `JsonDocument` | Caller-owned |

## Placement semantics

`Strata::Placement::Internal` forces the requested allocation into internal memory.

`Strata::Placement::PreferExternal` tries external RAM first and falls back to internal memory. This is the default for both Seal-owned movable storage and the worker task stack.

`Strata::Placement::RequireExternal` requires external RAM. Allocation or initialization fails instead of silently falling back if external RAM is unavailable.

`Strata::Placement::Default` delegates placement to the Strata backend.

## `SealToken`

`SealToken` owns generated token memory. It is move-only. The token contents are securely cleared before the Strata allocation is released.

For deterministic caller-owned output storage, use the buffer overload:

```cpp
char token[512];
size_t written = 0;
seal.sign(payload, options, secret, token, sizeof(token), written);
```

Seal never frees or relocates caller-owned buffers.

## Async Jobs

Async calls copy the serialized payload, token string, secret, options, and callback before returning. The job object and its owned string storage use `memory.allocation`.

During `deinit()`, queued async jobs that have not started may be securely discarded without invoking callbacks. Copied payload/token/secret bytes are cleared before Strata releases the job storage.

The async queue uses Strata static FreeRTOS ownership: queue item storage follows `memory.allocation`, while its FreeRTOS control block remains internal.

## Worker task and shutdown

The async worker is owned by `Strata::FreeRTOS::Task`. Its stack follows `memory.taskStack`; its FreeRTOS control block stays internal.

On shutdown the worker signals a Strata static binary semaphore, suspends itself, and lets `deinit()` delete the task from another task context. This allows Strata to safely release the worker's static stack and task-control allocation after execution has stopped.

## Sensitive data

Strata is responsible for allocation ownership and placement. Seal remains responsible for security semantics. Secrets, queued token copies, generated token buffers, and cryptographic signature buffers are cleared before their storage is released whenever Seal owns that storage.
