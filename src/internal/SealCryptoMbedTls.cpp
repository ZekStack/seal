#include "SealCrypto.h"

#if defined(ESP32) || !defined(SEAL_HOST_CRYPTO_OPENSSL)
#include <mbedtls/md.h>

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

	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (info == nullptr) {
		return SealResult::failure(SealCode::CryptoError, "sha256 unavailable");
	}

	const int rc = mbedtls_md_hmac(info, key, keyLength, data, dataLength, outSignature);
	if (rc != 0) {
		return SealResult::failure(SealCode::CryptoError, "hmac sha256 failed");
	}
	return SealResult::success();
}

const char *cryptoBackendName() {
	return "mbedtls";
}

} // namespace seal::internal
#endif
