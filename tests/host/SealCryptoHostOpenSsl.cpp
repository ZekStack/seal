#include "internal/SealCrypto.h"

#if defined(SEAL_HOST_CRYPTO_OPENSSL)
#include <openssl/hmac.h>

namespace seal::internal {

SealResult hmacSha256(
    const uint8_t *key,
    size_t keyLength,
    const uint8_t *data,
    size_t dataLength,
    uint8_t outSignature[kHs256SignatureBytes]
) {
	if ((key == nullptr && keyLength > 0) || (data == nullptr && dataLength > 0) ||
	    outSignature == nullptr) {
		return SealResult::failure(SealCode::InvalidArgument, "invalid crypto argument");
	}

	unsigned int length = 0;
	unsigned char *result = HMAC(
	    EVP_sha256(),
	    key,
	    static_cast<int>(keyLength),
	    data,
	    dataLength,
	    outSignature,
	    &length
	);
	if (result == nullptr || length != kHs256SignatureBytes) {
		return SealResult::failure(SealCode::CryptoError, "hmac sha256 failed");
	}
	return SealResult::success();
}

const char *cryptoBackendName() {
	return "openssl-host-test";
}

} // namespace seal::internal
#endif
