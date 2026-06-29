#pragma once

#include "../Seal.h"

#include <cstddef>
#include <cstdint>

namespace seal::internal {

constexpr size_t kHs256SignatureBytes = 32;

SealResult hmacSha256(
    const uint8_t *key,
    size_t keyLength,
    const uint8_t *data,
    size_t dataLength,
    uint8_t outSignature[kHs256SignatureBytes]
);

bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t length);
void secureClear(void *data, size_t length);
const char *cryptoBackendName();

} // namespace seal::internal
