#include <Seal.h>

#include <cstdio>
#include <cstring>

namespace {
constexpr const char *kSecret = "super-secret";

SealVerifyOptions compatVerifyOptions() {
	SealVerifyOptions options;
	options.issuer = "issuer-1";
	options.subject = "device-01";
	options.audience = "api";
	options.jwtid = "jwt-1";
	options.useClockTimestamp = true;
	options.clockTimestamp = 150;
	options.maxAgeSeconds = 100;
	return options;
}

int printResult(const SealResult &result) {
	if (result) {
		std::puts("OK");
		return 0;
	}
	std::fprintf(stderr, "%s\n", result.message);
	return static_cast<int>(result.code) == 0 ? 1 : static_cast<int>(result.code);
}
} // namespace

int main(int argc, char **argv) {
	if (argc < 2) {
		std::fprintf(stderr, "usage: seal_compat_cli sign|verify [token]\n");
		return 1;
	}

	Seal seal;
	SealConfig config;
	config.enableAsync = false;
	SealResult result = seal.init(config);
	if (!result) {
		return printResult(result);
	}

	if (std::strcmp(argv[1], "sign") == 0) {
		JsonDocument payload;
		payload["deviceId"] = "panel-01";

		SealOptions options;
		options.noTimestamp = true;
		options.issuer = "issuer-1";
		options.subject = "device-01";
		options.audience = "api";
		options.jwtid = "jwt-1";
		options.iat = 100;
		options.nbf = 90;
		options.exp = 200;

		SealToken token;
		result = seal.sign(payload, options, kSecret, token);
		if (!result) {
			return printResult(result);
		}
		std::puts(token.c_str());
		return 0;
	}

	if (std::strcmp(argv[1], "verify") == 0) {
		if (argc < 3) {
			std::fprintf(stderr, "verify requires token\n");
			return 1;
		}
		JsonDocument payload;
		result = seal.verify(argv[2], kSecret, compatVerifyOptions(), payload);
		if (!result) {
			return printResult(result);
		}
		const char *deviceId = payload["deviceId"] | "";
		if (std::strcmp(deviceId, "panel-01") != 0) {
			std::fprintf(stderr, "unexpected deviceId: %s\n", deviceId);
			return 1;
		}
		std::puts("OK");
		return 0;
	}

	std::fprintf(stderr, "unknown command: %s\n", argv[1]);
	return 1;
}
