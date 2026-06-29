#include <Seal.h>
#include <internal/SealBase64Url.h>
#include <internal/SealCrypto.h>

#include <cstdio>
#include <cstring>

namespace {
int failureCount = 0;

void expect(bool condition, const char *message) {
	if (condition) {
		return;
	}
	std::printf("FAIL: %s\n", message);
	failureCount++;
}

void testBase64Url() {
	char out[64] = {};
	size_t written = 0;
	SealResult result = seal::internal::base64UrlEncode(
	    reinterpret_cast<const uint8_t *>("hello?"),
	    6,
	    out,
	    sizeof(out),
	    written
	);
	expect(result && std::strcmp(out, "aGVsbG8_") == 0 && written == 8, "base64url encode");

	uint8_t decoded[64] = {};
	result = seal::internal::base64UrlDecode(out, written, decoded, sizeof(decoded), written);
	expect(result && written == 6 && std::memcmp(decoded, "hello?", 6) == 0, "base64url decode");

	result = seal::internal::base64UrlDecode("abc*", 4, decoded, sizeof(decoded), written);
	expect(!result && result.code == SealCode::MalformedToken, "base64url invalid char");

	result = seal::internal::base64UrlDecode("a", 1, decoded, sizeof(decoded), written);
	expect(!result && result.code == SealCode::MalformedToken, "base64url invalid length");
}

void testCryptoBoundary() {
	uint8_t signature[seal::internal::kHs256SignatureBytes] = {};
	SealResult result = seal::internal::hmacSha256(
	    reinterpret_cast<const uint8_t *>("key"),
	    3,
	    reinterpret_cast<const uint8_t *>("The quick brown fox jumps over the lazy dog"),
	    43,
	    signature
	);
	expect(static_cast<bool>(result), "hmac sha256 succeeds");

	const uint8_t expected[seal::internal::kHs256SignatureBytes] = {
	    0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
	    0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
	    0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
	    0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8,
	};
	expect(
	    seal::internal::constantTimeEqual(signature, expected, sizeof(signature)),
	    "hmac sha256 known vector"
	);

	signature[0] ^= 0x01;
	expect(
	    !seal::internal::constantTimeEqual(signature, expected, sizeof(signature)),
	    "constant time compare detects mismatch"
	);
	expect(std::strcmp(seal::internal::cryptoBackendName(), "openssl-host-test") == 0,
	    "host crypto backend name");
}
} // namespace

int main() {
	testBase64Url();
	testCryptoBoundary();

	if (failureCount != 0) {
		std::printf("%d host tests failed\n", failureCount);
		return 1;
	}

	std::printf("host tests passed\n");
	return 0;
}
