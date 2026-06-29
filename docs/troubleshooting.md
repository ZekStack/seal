# Troubleshooting

## `ClockUnavailable`

The token contains `exp` or `nbf`, or verification uses `maxAgeSeconds`, but Seal has no clock. Set a time provider or pass `clockTimestamp` in `SealVerifyOptions`.

## `InvalidSignature`

The token was changed, the wrong secret was used, or the signature segment is malformed.

## `AlgorithmMismatch`

Seal v0.1 supports only HS256. Tokens with `alg` values such as `none`, `RS256`, or `ES256` are rejected.

## `BufferTooSmall`

The payload, header, token, or caller-provided output buffer is smaller than required. Increase `SealConfig` limits or provide a larger output buffer.

## Async Callback Did Not Run

Confirm `SealConfig::enableAsync` is true and the async submit call returned success.
