#include "SealCrypto.h"

namespace seal::internal {

bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t length) {
	if (a == nullptr || b == nullptr) {
		return false;
	}

	uint8_t diff = 0;
	for (size_t i = 0; i < length; ++i) {
		diff |= static_cast<uint8_t>(a[i] ^ b[i]);
	}
	return diff == 0;
}

void secureClear(void *data, size_t length) {
	if (data == nullptr) {
		return;
	}
	volatile uint8_t *cursor = static_cast<volatile uint8_t *>(data);
	while (length-- > 0) {
		*cursor++ = 0;
	}
}

} // namespace seal::internal
