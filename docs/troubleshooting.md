# Troubleshooting

## `ClockUnavailable`

The token contains `exp` or `nbf`, or verification uses `maxAgeSeconds`, but Seal has no clock. Set a time provider or pass `clockTimestamp` in `SealVerifyOptions`.

## `InvalidSignature`

The token was changed, the wrong secret was used, or the signature segment is malformed.

## `AlgorithmMismatch`

Seal v0.2 supports only HS256. Tokens with `alg` values such as `none`, `RS256`, or `ES256` are rejected.

## `BufferTooSmall`

The payload, header, token, or caller-provided output buffer is smaller than required. Increase `SealConfig` limits or provide a larger output buffer.

## `AllocationFailed` with `RequireExternal`

`Strata::Placement::RequireExternal` intentionally does not fall back to internal memory. If PSRAM/external RAM is unavailable or exhausted, token/job/queue allocation can fail through `memory.allocation`, and async initialization can fail through `memory.taskStack`.

Use `Strata::Placement::PreferExternal` when external RAM is preferred but internal fallback is acceptable, or `Strata::Placement::Internal` when the resource must remain internal.

## Async Callback Did Not Run

Confirm `SealConfig::enableAsync` is true and the async submit call returned success.

## `Busy` During Shutdown

Seal returns `Busy` while shutdown is in progress, while an async callback is running, or if `deinit()` is called from the worker task. Call `deinit()` again later if a previous shutdown attempt timed out.
