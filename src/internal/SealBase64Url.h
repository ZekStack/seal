#pragma once

#include "../Seal.h"

#include <cstddef>
#include <cstdint>

namespace seal::internal {

size_t base64UrlEncodedLength(size_t inputLength, bool padding = false);
size_t base64UrlDecodedMaxLength(size_t inputLength);

SealResult base64UrlEncode(
    const uint8_t *input,
    size_t inputLength,
    char *output,
    size_t outputSize,
    size_t &written
);

SealResult base64UrlDecode(
    const char *input,
    size_t inputLength,
    uint8_t *output,
    size_t outputSize,
    size_t &written
);

} // namespace seal::internal
