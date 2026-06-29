#include "SealBase64Url.h"

namespace {
constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int decodeChar(char value) {
	if (value >= 'A' && value <= 'Z') {
		return value - 'A';
	}
	if (value >= 'a' && value <= 'z') {
		return value - 'a' + 26;
	}
	if (value >= '0' && value <= '9') {
		return value - '0' + 52;
	}
	if (value == '-') {
		return 62;
	}
	if (value == '_') {
		return 63;
	}
	return -1;
}
} // namespace

namespace seal::internal {

size_t base64UrlEncodedLength(size_t inputLength, bool padding) {
	const size_t padded = ((inputLength + 2) / 3) * 4;
	if (padding || inputLength == 0) {
		return padded;
	}
	const size_t remainder = inputLength % 3;
	if (remainder == 0) {
		return padded;
	}
	return padded - (3 - remainder);
}

size_t base64UrlDecodedMaxLength(size_t inputLength) {
	return ((inputLength + 3) / 4) * 3;
}

SealResult base64UrlEncode(
    const uint8_t *input,
    size_t inputLength,
    char *output,
    size_t outputSize,
    size_t &written
) {
	written = 0;
	if ((input == nullptr && inputLength > 0) || output == nullptr) {
		return SealResult::failure(SealCode::InvalidArgument, "invalid base64url encode argument");
	}

	const size_t needed = base64UrlEncodedLength(inputLength, false);
	if (outputSize <= needed) {
		return SealResult::failure(SealCode::BufferTooSmall, "base64url output buffer too small");
	}

	size_t in = 0;
	size_t out = 0;
	while (in + 3 <= inputLength) {
		const uint32_t block =
		    (static_cast<uint32_t>(input[in]) << 16) |
		    (static_cast<uint32_t>(input[in + 1]) << 8) |
		    static_cast<uint32_t>(input[in + 2]);
		output[out++] = kAlphabet[(block >> 18) & 0x3F];
		output[out++] = kAlphabet[(block >> 12) & 0x3F];
		output[out++] = kAlphabet[(block >> 6) & 0x3F];
		output[out++] = kAlphabet[block & 0x3F];
		in += 3;
	}

	const size_t remaining = inputLength - in;
	if (remaining == 1) {
		const uint32_t block = static_cast<uint32_t>(input[in]) << 16;
		output[out++] = kAlphabet[(block >> 18) & 0x3F];
		output[out++] = kAlphabet[(block >> 12) & 0x3F];
	} else if (remaining == 2) {
		const uint32_t block =
		    (static_cast<uint32_t>(input[in]) << 16) |
		    (static_cast<uint32_t>(input[in + 1]) << 8);
		output[out++] = kAlphabet[(block >> 18) & 0x3F];
		output[out++] = kAlphabet[(block >> 12) & 0x3F];
		output[out++] = kAlphabet[(block >> 6) & 0x3F];
	}

	output[out] = '\0';
	written = out;
	return SealResult::success();
}

SealResult base64UrlDecode(
    const char *input,
    size_t inputLength,
    uint8_t *output,
    size_t outputSize,
    size_t &written
) {
	written = 0;
	if ((input == nullptr && inputLength > 0) || output == nullptr) {
		return SealResult::failure(SealCode::InvalidArgument, "invalid base64url decode argument");
	}
	if (inputLength == 0) {
		return SealResult::success();
	}

	size_t unpaddedLength = inputLength;
	while (unpaddedLength > 0 && input[unpaddedLength - 1] == '=') {
		unpaddedLength--;
	}
	for (size_t i = 0; i < unpaddedLength; ++i) {
		if (input[i] == '=') {
			return SealResult::failure(SealCode::MalformedToken, "malformed base64url padding");
		}
	}

	if ((unpaddedLength % 4) == 1) {
		return SealResult::failure(SealCode::MalformedToken, "malformed base64url length");
	}

	const size_t remainder = unpaddedLength % 4;
	const size_t expected =
	    (unpaddedLength / 4) * 3 + (remainder == 2 ? 1 : (remainder == 3 ? 2 : 0));
	if (outputSize < expected) {
		return SealResult::failure(SealCode::BufferTooSmall, "base64url decode buffer too small");
	}

	size_t in = 0;
	size_t out = 0;
	while (in + 4 <= unpaddedLength) {
		const int a = decodeChar(input[in]);
		const int b = decodeChar(input[in + 1]);
		const int c = decodeChar(input[in + 2]);
		const int d = decodeChar(input[in + 3]);
		if (a < 0 || b < 0 || c < 0 || d < 0) {
			return SealResult::failure(SealCode::MalformedToken, "invalid base64url character");
		}
		const uint32_t block =
		    (static_cast<uint32_t>(a) << 18) | (static_cast<uint32_t>(b) << 12) |
		    (static_cast<uint32_t>(c) << 6) | static_cast<uint32_t>(d);
		output[out++] = static_cast<uint8_t>((block >> 16) & 0xFF);
		output[out++] = static_cast<uint8_t>((block >> 8) & 0xFF);
		output[out++] = static_cast<uint8_t>(block & 0xFF);
		in += 4;
	}

	if (remainder == 2) {
		const int a = decodeChar(input[in]);
		const int b = decodeChar(input[in + 1]);
		if (a < 0 || b < 0) {
			return SealResult::failure(SealCode::MalformedToken, "invalid base64url character");
		}
		const uint32_t block = (static_cast<uint32_t>(a) << 18) |
		                       (static_cast<uint32_t>(b) << 12);
		output[out++] = static_cast<uint8_t>((block >> 16) & 0xFF);
	} else if (remainder == 3) {
		const int a = decodeChar(input[in]);
		const int b = decodeChar(input[in + 1]);
		const int c = decodeChar(input[in + 2]);
		if (a < 0 || b < 0 || c < 0) {
			return SealResult::failure(SealCode::MalformedToken, "invalid base64url character");
		}
		const uint32_t block =
		    (static_cast<uint32_t>(a) << 18) | (static_cast<uint32_t>(b) << 12) |
		    (static_cast<uint32_t>(c) << 6);
		output[out++] = static_cast<uint8_t>((block >> 16) & 0xFF);
		output[out++] = static_cast<uint8_t>((block >> 8) & 0xFF);
	}

	written = out;
	return SealResult::success();
}

} // namespace seal::internal
