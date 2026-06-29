#include <Seal.h>
#include <internal/SealBase64Url.h>
#include <internal/SealCrypto.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {
constexpr const char *kSecret = "super-secret";
int failureCount = 0;

void expect(bool condition, const char *message) {
	if (condition) {
		return;
	}
	std::printf("FAIL: %s\n", message);
	++failureCount;
}

void expect(const SealResult &result, const char *message) {
	if (result) {
		return;
	}
	std::printf("FAIL: %s: %s\n", message, result.message);
	++failureCount;
}

void expectCode(const SealResult &result, SealCode code, const char *message) {
	if (result.code == code) {
		return;
	}
	std::printf("FAIL: %s: expected %u got %u (%s)\n",
	    message,
	    static_cast<unsigned>(code),
	    static_cast<unsigned>(result.code),
	    result.message);
	++failureCount;
}

std::string encodeSegment(const std::string &input) {
	std::vector<char> output(seal::internal::base64UrlEncodedLength(input.size()) + 1);
	size_t written = 0;
	SealResult result = seal::internal::base64UrlEncode(
	    reinterpret_cast<const uint8_t *>(input.data()),
	    input.size(),
	    output.data(),
	    output.size(),
	    written
	);
	expect(result, "test helper base64url encode");
	return std::string(output.data(), written);
}

std::string signInput(const std::string &signingInput, const char *secret) {
	uint8_t signature[seal::internal::kHs256SignatureBytes] = {};
	SealResult result = seal::internal::hmacSha256(
	    reinterpret_cast<const uint8_t *>(secret),
	    std::strlen(secret),
	    reinterpret_cast<const uint8_t *>(signingInput.data()),
	    signingInput.size(),
	    signature
	);
	expect(result, "test helper hmac");

	std::vector<char> output(seal::internal::base64UrlEncodedLength(sizeof(signature)) + 1);
	size_t written = 0;
	result = seal::internal::base64UrlEncode(
	    signature,
	    sizeof(signature),
	    output.data(),
	    output.size(),
	    written
	);
	seal::internal::secureClear(signature, sizeof(signature));
	expect(result, "test helper signature encode");
	return std::string(output.data(), written);
}

std::string tokenFromJson(
    const std::string &headerJson,
    const std::string &payloadJson,
    const char *secret = kSecret
) {
	std::string signingInput = encodeSegment(headerJson) + "." + encodeSegment(payloadJson);
	return signingInput + "." + signInput(signingInput, secret);
}

std::string signStandardToken(Seal &seal) {
	JsonDocument payload;
	payload["deviceId"] = "panel-01";

	SealOptions options;
	options.noTimestamp = true;
	options.issuer = "issuer-1";
	options.subject = "subject-1";
	options.audience = "audience-1";
	options.jwtid = "jwt-1";
	options.iat = 100;
	options.nbf = 90;
	options.exp = 200;

	SealToken token;
	SealResult result = seal.sign(payload, options, kSecret, token);
	expect(result, "standard sign succeeds");
	return token.c_str();
}

std::string replacePayloadKeepSignature(const std::string &token, const std::string &payloadJson) {
	const size_t firstDot = token.find('.');
	const size_t secondDot = token.find('.', firstDot + 1);
	return token.substr(0, firstDot + 1) + encodeSegment(payloadJson) + token.substr(secondDot);
}

std::string replaceSignature(const std::string &token, const std::string &signature) {
	const size_t secondDot = token.find('.', token.find('.') + 1);
	return token.substr(0, secondDot + 1) + signature;
}

SealVerifyOptions standardVerifyOptions(uint64_t now = 150) {
	SealVerifyOptions options;
	options.issuer = "issuer-1";
	options.subject = "subject-1";
	options.audience = "audience-1";
	options.jwtid = "jwt-1";
	options.useClockTimestamp = true;
	options.clockTimestamp = now;
	return options;
}

void testSignVerifyDecode() {
	Seal seal;
	expect(seal.init(), "init succeeds");

	const std::string token = signStandardToken(seal);
	JsonDocument verified;
	SealResult result = seal.verify(token.c_str(), kSecret, standardVerifyOptions(), verified);
	expect(result, "verify signed token succeeds");
	expect(std::strcmp(verified["deviceId"] | "", "panel-01") == 0, "verified payload value");

	result = seal.verify(token.c_str(), "wrong-secret", standardVerifyOptions(), verified);
	expectCode(result, SealCode::InvalidSignature, "wrong secret rejected");

	const std::string tamperedPayload =
	    replacePayloadKeepSignature(token, "{\"deviceId\":\"panel-02\",\"iat\":100,\"nbf\":90,\"exp\":200}");
	result = seal.verify(tamperedPayload.c_str(), kSecret, standardVerifyOptions(), verified);
	expectCode(result, SealCode::InvalidSignature, "tampered payload rejected");

	const std::string tamperedSignature = replaceSignature(token, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	result = seal.verify(tamperedSignature.c_str(), kSecret, standardVerifyOptions(), verified);
	expectCode(result, SealCode::InvalidSignature, "tampered signature rejected");

	JsonDocument decoded;
	result = seal.decode(token.c_str(), decoded);
	expect(result, "unsafe decode succeeds");
	expect(std::strcmp(decoded["deviceId"] | "", "panel-01") == 0, "decoded payload value");

	expect(seal.deinit(), "deinit succeeds");
	result = seal.decode(token.c_str(), decoded);
	expectCode(result, SealCode::NotInitialized, "sync decode after deinit rejected");
	result = seal.deinit();
	expect(result, "deinit twice is ok");
}

void testMalformedTokens() {
	Seal seal;
	expect(seal.init(), "init for malformed tests");
	JsonDocument out;

	SealResult result = seal.verify("abc.def", kSecret, out);
	expectCode(result, SealCode::MalformedToken, "two segment token rejected");

	result = seal.verify("abc.def.ghi.jkl", kSecret, out);
	expectCode(result, SealCode::MalformedToken, "four segment token rejected");

	result = seal.verify("abc*.def.ghi", kSecret, out);
	expectCode(result, SealCode::InvalidHeader, "invalid base64url rejected");

	std::string token = encodeSegment("not-json") + "." + encodeSegment("{}") + ".sig";
	result = seal.verify(token.c_str(), kSecret, out);
	expectCode(result, SealCode::InvalidHeader, "invalid header json rejected");

	token = encodeSegment("{\"alg\":\"HS256\"}") + "." + encodeSegment("not-json") + ".sig";
	result = seal.verify(token.c_str(), kSecret, out);
	expectCode(result, SealCode::InvalidPayload, "invalid payload json rejected");

	token = tokenFromJson("{\"alg\":\"HS256\"}", "{\"sub\":\"subject-1\"}");
	token = token.substr(0, token.rfind('.') + 1);
	result = seal.verify(token.c_str(), kSecret, out);
	expectCode(result, SealCode::SignatureRequired, "empty signature rejected");

	expect(seal.deinit(), "deinit malformed tests");
}

void testAlgorithmAndTyp() {
	Seal seal;
	expect(seal.init(), "init for alg tests");
	JsonDocument out;

	SealResult result =
	    seal.verify(tokenFromJson("{\"typ\":\"JWT\"}", "{\"sub\":\"subject-1\"}").c_str(), kSecret, out);
	expectCode(result, SealCode::InvalidHeader, "missing alg rejected");

	result =
	    seal.verify(tokenFromJson("{\"alg\":null}", "{\"sub\":\"subject-1\"}").c_str(), kSecret, out);
	expectCode(result, SealCode::InvalidHeader, "null alg rejected");

	result =
	    seal.verify(tokenFromJson("{\"alg\":\"none\"}", "{\"sub\":\"subject-1\"}").c_str(), kSecret, out);
	expectCode(result, SealCode::AlgorithmMismatch, "alg none rejected");

	result =
	    seal.verify(tokenFromJson("{\"alg\":\"HS384\"}", "{\"sub\":\"subject-1\"}").c_str(), kSecret, out);
	expectCode(result, SealCode::AlgorithmMismatch, "alg HS384 rejected");

	result =
	    seal.verify(tokenFromJson("{\"alg\":\"RS256\"}", "{\"sub\":\"subject-1\"}").c_str(), kSecret, out);
	expectCode(result, SealCode::AlgorithmMismatch, "alg RS256 rejected");

	result = seal.verify(
	    tokenFromJson("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"sub\":\"subject-1\"}").c_str(),
	    kSecret,
	    out
	);
	expect(result, "typ JWT accepted");

	result = seal.verify(
	    tokenFromJson("{\"alg\":\"HS256\",\"typ\":\"jwt\"}", "{\"sub\":\"subject-1\"}").c_str(),
	    kSecret,
	    out
	);
	expect(result, "typ jwt ignored");

	result = seal.verify(
	    tokenFromJson("{\"alg\":\"HS256\",\"typ\":\"not-jwt\"}", "{\"sub\":\"subject-1\"}").c_str(),
	    kSecret,
	    out
	);
	expect(result, "typ not-jwt ignored");

	expect(seal.deinit(), "deinit alg tests");
}

void testClaimsAndLimits() {
	Seal seal;
	expect(seal.init(), "init for claims tests");
	const std::string token = signStandardToken(seal);
	JsonDocument out;

	SealVerifyOptions options = standardVerifyOptions();
	options.issuer = "wrong";
	expectCode(seal.verify(token.c_str(), kSecret, options, out), SealCode::IssuerMismatch, "issuer mismatch");

	options = standardVerifyOptions();
	options.subject = "wrong";
	expectCode(seal.verify(token.c_str(), kSecret, options, out), SealCode::SubjectMismatch, "subject mismatch");

	options = standardVerifyOptions();
	options.audience = "wrong";
	expectCode(
	    seal.verify(token.c_str(), kSecret, options, out),
	    SealCode::AudienceMismatch,
	    "audience mismatch"
	);

	options = standardVerifyOptions();
	options.jwtid = "wrong";
	expectCode(seal.verify(token.c_str(), kSecret, options, out), SealCode::JwtIdMismatch, "jwt id mismatch");

	JsonDocument payload;
	payload["data"] = "abcdefghijklmnopqrstuvwxyz";
	SealOptions signOptions;
	signOptions.noTimestamp = true;
	char smallBuffer[16] = {};
	size_t written = 0;
	expectCode(
	    seal.sign(payload, signOptions, kSecret, smallBuffer, sizeof(smallBuffer), written),
	    SealCode::BufferTooSmall,
	    "caller buffer too small"
	);

	expect(seal.deinit(), "deinit claims tests");

	SealConfig config;
	config.maxPayloadSize = 8;
	config.enableAsync = false;
	expect(seal.init(config), "init small payload seal");
	expectCode(
	    seal.sign(payload, signOptions, kSecret, smallBuffer, sizeof(smallBuffer), written),
	    SealCode::BufferTooSmall,
	    "sign payload too large rejected"
	);

	const std::string oversizedPayloadToken =
	    tokenFromJson("{\"alg\":\"HS256\"}", "{\"data\":\"abcdefghijklmnopqrstuvwxyz\"}");
	expectCode(
	    seal.verify(oversizedPayloadToken.c_str(), kSecret, out),
	    SealCode::BufferTooSmall,
	    "verify decoded payload too large rejected"
	);
	expect(seal.deinit(), "deinit small payload seal");

	config = SealConfig();
	config.maxTokenSize = 64;
	config.enableAsync = false;
	expect(seal.init(config), "init small token seal");
	expectCode(
	    seal.verify(token.c_str(), kSecret, out),
	    SealCode::BufferTooSmall,
	    "max token size exceeded rejected"
	);
	expect(seal.deinit(), "deinit small token seal");
}

void testTimeBoundaries() {
	Seal seal;
	expect(seal.init(), "init time tests");
	JsonDocument out;

	const std::string expToken = tokenFromJson("{\"alg\":\"HS256\"}", "{\"exp\":100}");
	SealVerifyOptions options;
	options.useClockTimestamp = true;
	options.clockTimestamp = 99;
	expect(seal.verify(expToken.c_str(), kSecret, options, out), "exp now one before accepted");
	options.clockTimestamp = 100;
	expectCode(seal.verify(expToken.c_str(), kSecret, options, out), SealCode::Expired, "exp at boundary expired");
	options.clockTimestamp = 101;
	expectCode(seal.verify(expToken.c_str(), kSecret, options, out), SealCode::Expired, "exp after boundary expired");
	options.clockToleranceSeconds = 1;
	options.clockTimestamp = 100;
	expect(seal.verify(expToken.c_str(), kSecret, options, out), "exp tolerance accepts boundary");
	options.clockTimestamp = 101;
	expectCode(seal.verify(expToken.c_str(), kSecret, options, out), SealCode::Expired, "exp tolerance expires after window");

	const std::string nbfToken = tokenFromJson("{\"alg\":\"HS256\"}", "{\"nbf\":100}");
	options = SealVerifyOptions();
	options.useClockTimestamp = true;
	options.clockTimestamp = 99;
	expectCode(seal.verify(nbfToken.c_str(), kSecret, options, out), SealCode::NotActive, "nbf before rejected");
	options.clockTimestamp = 100;
	expect(seal.verify(nbfToken.c_str(), kSecret, options, out), "nbf boundary accepted");
	options.clockTimestamp = 101;
	expect(seal.verify(nbfToken.c_str(), kSecret, options, out), "nbf after accepted");
	options.clockToleranceSeconds = 1;
	options.clockTimestamp = 98;
	expectCode(seal.verify(nbfToken.c_str(), kSecret, options, out), SealCode::NotActive, "nbf outside tolerance rejected");
	options.clockTimestamp = 99;
	expect(seal.verify(nbfToken.c_str(), kSecret, options, out), "nbf tolerance accepts one before");

	const std::string iatToken = tokenFromJson("{\"alg\":\"HS256\"}", "{\"iat\":100}");
	options = SealVerifyOptions();
	options.useClockTimestamp = true;
	options.maxAgeSeconds = 10;
	options.clockTimestamp = 109;
	expect(seal.verify(iatToken.c_str(), kSecret, options, out), "maxAge before boundary accepted");
	options.clockTimestamp = 110;
	expectCode(seal.verify(iatToken.c_str(), kSecret, options, out), SealCode::Expired, "maxAge boundary expired");
	options.clockTimestamp = 111;
	expectCode(seal.verify(iatToken.c_str(), kSecret, options, out), SealCode::Expired, "maxAge after expired");
	options.clockToleranceSeconds = 1;
	options.clockTimestamp = 110;
	expect(seal.verify(iatToken.c_str(), kSecret, options, out), "maxAge tolerance accepts boundary");
	options.clockTimestamp = 111;
	expectCode(seal.verify(iatToken.c_str(), kSecret, options, out), SealCode::Expired, "maxAge tolerance expires after window");

	expect(seal.deinit(), "deinit time tests");
}

void testPaddingAndDefaultIat() {
	Seal seal;
	expect(seal.init(), "init padding tests");
	const std::string token = signStandardToken(seal);
	const size_t firstDot = token.find('.');
	const size_t secondDot = token.find('.', firstDot + 1);
	const std::string padded = token.substr(0, firstDot) + "==." +
	                           token.substr(firstDot + 1, secondDot - firstDot - 1) + "=." +
	                           token.substr(secondDot + 1) + "=";
	JsonDocument out;
	expect(seal.decode(padded.c_str(), out), "decode accepts padded base64url segments");

	JsonDocument payload;
	payload["deviceId"] = "panel-01";
	SealToken noClockToken;
	expect(seal.sign(payload, kSecret, noClockToken), "sign without clock succeeds");
	JsonDocument decoded;
	expect(seal.decode(noClockToken.c_str(), decoded), "decode no-clock token");
	expect(decoded["iat"].isNull(), "default iat skipped when clock unavailable");

	expect(seal.deinit(), "deinit padding tests");
}

void testStoppedLifecycle() {
	Seal seal;
	JsonDocument payload;
	payload["deviceId"] = "panel-01";
	JsonDocument out;

	expect(!seal.initialized(), "new seal is not initialized");
	expectCode(seal.setClockTimestamp(100), SealCode::NotInitialized, "clock setter before init rejected");
	expectCode(seal.sign(payload, kSecret, [](SealResult, SealToken) {}), SealCode::NotInitialized, "async sign before init rejected");
	expectCode(seal.verify("a.b.c", kSecret, out), SealCode::NotInitialized, "sync verify before init rejected");
	expect(seal.deinit(), "deinit while stopped is ok");

	SealConfig config;
	config.enableAsync = false;
	expect(seal.init(config), "init stopped lifecycle");
	expect(seal.deinit(), "deinit stopped lifecycle");
	expect(!seal.initialized(), "deinitialized seal is not initialized");
	expectCode(seal.sign(payload, kSecret, [](SealResult, SealToken) {}), SealCode::NotInitialized, "async sign after deinit rejected");
	expectCode(seal.decode("a.b.c", out), SealCode::NotInitialized, "sync decode after deinit rejected");
	expect(seal.deinit(), "second deinit after stopped lifecycle is ok");
}
} // namespace

int main() {
	testSignVerifyDecode();
	testMalformedTokens();
	testAlgorithmAndTyp();
	testClaimsAndLimits();
	testTimeBoundaries();
	testPaddingAndDefaultIat();
	testStoppedLifecycle();

	if (failureCount != 0) {
		std::printf("%d seal jwt tests failed\n", failureCount);
		return 1;
	}

	std::printf("seal jwt tests passed\n");
	return 0;
}
