#include "Seal.h"

#include "internal/SealBase64Url.h"
#include "internal/SealCrypto.h"
#include "internal/SealMemory.h"
#include "internal/SealMutex.h"
#include "internal/SealTaskSupport.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <vector>

#if defined(ESP32)
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#endif

namespace {

enum class SealJobType : uint8_t {
	Sign,
	Verify,
	Decode,
};

enum class SealLifecycle : uint8_t {
	Stopped,
	Running,
	Stopping,
};

bool isEmpty(const char *value) {
	return value == nullptr || value[0] == '\0';
}

size_t cstringLength(const char *value) {
	return value == nullptr ? 0 : std::strlen(value);
}

SealResult validateConfig(const SealConfig &config) {
	if (config.maxTokenSize < 64 || config.maxPayloadSize == 0 || config.maxHeaderSize == 0 ||
	    config.maxSignatureSize < 43) {
		return SealResult::failure(SealCode::InvalidArgument, "invalid seal size limits");
	}
	if (config.enableAsync && (config.queueSize == 0 || config.stackSizeBytes < 1024)) {
		return SealResult::failure(SealCode::InvalidArgument, "invalid async configuration");
	}
	return SealResult::success();
}

SealResult serializeDocument(const JsonDocument &doc, size_t maxBytes, std::string &out) {
	const size_t measured = measureJson(doc);
	if (measured == 0) {
		return SealResult::failure(SealCode::InvalidPayload, "json payload is empty");
	}
	if (measured > maxBytes) {
		return SealResult::failure(SealCode::BufferTooSmall, "json exceeds configured size limit");
	}

	std::vector<char> buffer(measured + 1);
	const size_t written = serializeJson(doc, buffer.data(), buffer.size());
	if (written == 0 || written > maxBytes) {
		return SealResult::failure(SealCode::JsonError, "json serialization failed");
	}

	out.assign(buffer.data(), written);
	return SealResult::success();
}

SealResult encodeString(const std::string &input, std::string &out) {
	const size_t capacity = seal::internal::base64UrlEncodedLength(input.size()) + 1;
	std::vector<char> buffer(capacity);
	size_t written = 0;
	SealResult result = seal::internal::base64UrlEncode(
	    reinterpret_cast<const uint8_t *>(input.data()),
	    input.size(),
	    buffer.data(),
	    buffer.size(),
	    written
	);
	if (!result) {
		return result;
	}
	out.assign(buffer.data(), written);
	return SealResult::success();
}

SealResult decodeStringSegment(const char *segment, size_t length, std::string &out) {
	if (segment == nullptr || length == 0) {
		return SealResult::failure(SealCode::MalformedToken, "empty jwt segment");
	}

	const size_t capacity = seal::internal::base64UrlDecodedMaxLength(length) + 1;
	std::vector<uint8_t> buffer(capacity);
	size_t written = 0;
	SealResult result = seal::internal::base64UrlDecode(
	    segment,
	    length,
	    buffer.data(),
	    buffer.size() - 1,
	    written
	);
	if (!result) {
		return result;
	}

	buffer[written] = 0;
	out.assign(reinterpret_cast<const char *>(buffer.data()), written);
	return SealResult::success();
}

struct TokenSegments {
	const char *header = nullptr;
	size_t headerLength = 0;
	const char *payload = nullptr;
	size_t payloadLength = 0;
	const char *signature = nullptr;
	size_t signatureLength = 0;
};

SealResult splitToken(const char *token, size_t maxTokenSize, TokenSegments &segments) {
	if (isEmpty(token)) {
		return SealResult::failure(SealCode::InvalidArgument, "token is required");
	}

	const size_t tokenLength = std::strlen(token);
	if (tokenLength > maxTokenSize) {
		return SealResult::failure(SealCode::BufferTooSmall, "token exceeds configured size limit");
	}

	const char *firstDot = std::strchr(token, '.');
	if (firstDot == nullptr) {
		return SealResult::failure(SealCode::MalformedToken, "jwt must have three segments");
	}
	const char *secondDot = std::strchr(firstDot + 1, '.');
	if (secondDot == nullptr || std::strchr(secondDot + 1, '.') != nullptr) {
		return SealResult::failure(SealCode::MalformedToken, "jwt must have three segments");
	}

	segments.header = token;
	segments.headerLength = static_cast<size_t>(firstDot - token);
	segments.payload = firstDot + 1;
	segments.payloadLength = static_cast<size_t>(secondDot - firstDot - 1);
	segments.signature = secondDot + 1;
	segments.signatureLength = std::strlen(secondDot + 1);

	if (segments.headerLength == 0 || segments.payloadLength == 0) {
		return SealResult::failure(SealCode::MalformedToken, "jwt header and payload are required");
	}

	return SealResult::success();
}

bool jsonStringEquals(JsonString actual, const char *expected) {
	if (expected == nullptr) {
		return true;
	}
	return actual && actual.size() == std::strlen(expected) &&
	       std::memcmp(actual.c_str(), expected, actual.size()) == 0;
}

bool stringClaimEquals(JsonDocument &payload, const char *claim, const char *expected) {
	if (expected == nullptr) {
		return true;
	}
	return jsonStringEquals(payload[claim].as<JsonString>(), expected);
}

bool getNumericClaim(JsonDocument &payload, const char *claim, uint64_t &out) {
	if (!payload[claim].is<uint64_t>()) {
		return false;
	}
	out = payload[claim].as<uint64_t>();
	return true;
}

SealResult resultForLifecycle(SealLifecycle lifecycle) {
	if (lifecycle == SealLifecycle::Stopped) {
		return SealResult::failure(SealCode::NotInitialized, "seal is not initialized");
	}
	return SealResult::failure(SealCode::Busy, "seal is stopping");
}

bool expiredAtOrAfter(uint64_t now, uint64_t boundary, uint32_t toleranceSeconds) {
	if (now < boundary) {
		return false;
	}
	return now - boundary >= static_cast<uint64_t>(toleranceSeconds);
}

bool notActiveBefore(uint64_t now, uint64_t notBefore, uint32_t toleranceSeconds) {
	return now < notBefore && notBefore - now > static_cast<uint64_t>(toleranceSeconds);
}

bool maxAgeExceeded(uint64_t now, uint64_t issuedAt, uint64_t maxAgeSeconds, uint32_t toleranceSeconds) {
	if (now < issuedAt) {
		return false;
	}
	const uint64_t age = now - issuedAt;
	if (age < maxAgeSeconds) {
		return false;
	}
	return age - maxAgeSeconds >= static_cast<uint64_t>(toleranceSeconds);
}

} // namespace

struct SealJob {
	SealJobType type = SealJobType::Decode;
	std::string payloadJson;
	std::string token;
	std::string secret;
	SealOptions signOptions;
	SealVerifyOptions verifyOptions;
	SealSignCallback signCallback;
	SealVerifyCallback verifyCallback;
	SealDecodeCallback decodeCallback;
};

struct SealImpl {
	SealConfig config{};
	SealMutex mutex;
	SealTimeProvider timeProvider;
	uint64_t fixedClockTimestamp = 0;
	bool useFixedClockTimestamp = false;
	SealLifecycle lifecycle = SealLifecycle::Stopped;
	bool stopRequested = false;
	uint16_t callbackDepth = 0;
#if defined(ESP32)
	QueueHandle_t queue = nullptr;
	TaskHandle_t task = nullptr;
	SemaphoreHandle_t doneSignal = nullptr;
	bool taskCreatedWithCaps = false;
#endif

	bool shouldPreferPsram() const {
		return config.preferPsram;
	}

	SealResult readClock(const SealVerifyOptions *options, uint64_t &out) {
		if (options != nullptr && options->useClockTimestamp) {
			out = options->clockTimestamp;
			return SealResult::success();
		}
		if (useFixedClockTimestamp) {
			out = fixedClockTimestamp;
			return SealResult::success();
		}
		if (timeProvider && timeProvider(out)) {
			return SealResult::success();
		}
		return SealResult::failure(SealCode::ClockUnavailable, "clock is unavailable");
	}

	SealResult allocateToken(const std::string &token, SealToken &outToken) {
		if (token.size() > config.maxTokenSize) {
			return SealResult::failure(SealCode::BufferTooSmall, "token exceeds configured size limit");
		}

		char *value = static_cast<char *>(seal::internal::allocate(token.size() + 1, shouldPreferPsram()));
		if (value == nullptr) {
			return SealResult::failure(SealCode::AllocationFailed, "token allocation failed");
		}

		std::memcpy(value, token.c_str(), token.size() + 1);
		outToken.clear();
		outToken.value = value;
		outToken.length = token.size();
		outToken.capacity = token.size() + 1;
		return SealResult::success();
	}

	SealResult buildSignedToken(
	    const JsonDocument &payload,
	    const SealOptions &options,
	    const char *secret,
		std::string &outToken
	) {
		outToken.clear();
		if (lifecycle != SealLifecycle::Running) {
			return resultForLifecycle(lifecycle);
		}
		if (isEmpty(secret)) {
			return SealResult::failure(SealCode::InvalidArgument, "secret is required");
		}
		if (options.algorithm != SealAlgorithm::HS256) {
			return SealResult::failure(SealCode::UnsupportedAlgorithm, "only HS256 is supported");
		}
		if (!payload.is<JsonObjectConst>()) {
			return SealResult::failure(SealCode::InvalidPayload, "jwt payload must be a json object");
		}

		JsonDocument header;
		header["alg"] = "HS256";
		header["typ"] = "JWT";
		if (!isEmpty(options.keyid)) {
			header["kid"] = options.keyid;
		}

		std::string headerJson;
		SealResult result = serializeDocument(header, config.maxHeaderSize, headerJson);
		if (!result) {
			if (result.code == SealCode::BufferTooSmall) {
				return result;
			}
			return SealResult::failure(SealCode::InvalidHeader, result.message);
		}

		JsonDocument workingPayload;
		workingPayload.set(payload.as<JsonObjectConst>());
		JsonObject object = workingPayload.as<JsonObject>();
		if (options.iat > 0) {
			object["iat"] = options.iat;
		} else if (!options.noTimestamp && config.addIssuedAtByDefault && object["iat"].isNull()) {
			uint64_t now = 0;
			if (readClock(nullptr, now)) {
				object["iat"] = now;
			}
		}
		if (options.exp > 0) {
			object["exp"] = options.exp;
		}
		if (options.nbf > 0) {
			object["nbf"] = options.nbf;
		}
		if (!isEmpty(options.issuer)) {
			object["iss"] = options.issuer;
		}
		if (!isEmpty(options.subject)) {
			object["sub"] = options.subject;
		}
		if (!isEmpty(options.audience)) {
			object["aud"] = options.audience;
		}
		if (!isEmpty(options.jwtid)) {
			object["jti"] = options.jwtid;
		}

		std::string payloadJson;
		result = serializeDocument(workingPayload, config.maxPayloadSize, payloadJson);
		if (!result) {
			if (result.code == SealCode::BufferTooSmall) {
				return result;
			}
			return SealResult::failure(SealCode::InvalidPayload, result.message);
		}

		std::string encodedHeader;
		std::string encodedPayload;
		result = encodeString(headerJson, encodedHeader);
		if (!result) {
			return result;
		}
		result = encodeString(payloadJson, encodedPayload);
		if (!result) {
			return result;
		}

		std::string signingInput = encodedHeader + "." + encodedPayload;
		uint8_t signature[seal::internal::kHs256SignatureBytes] = {0};
		result = seal::internal::hmacSha256(
		    reinterpret_cast<const uint8_t *>(secret),
		    cstringLength(secret),
		    reinterpret_cast<const uint8_t *>(signingInput.data()),
		    signingInput.size(),
		    signature
		);
		if (!result) {
			seal::internal::secureClear(signature, sizeof(signature));
			return result;
		}

		const size_t encodedSignatureCapacity =
		    seal::internal::base64UrlEncodedLength(sizeof(signature)) + 1;
		std::vector<char> encodedSignature(encodedSignatureCapacity);
		size_t signatureWritten = 0;
		result = seal::internal::base64UrlEncode(
		    signature,
		    sizeof(signature),
		    encodedSignature.data(),
		    encodedSignature.size(),
		    signatureWritten
		);
		seal::internal::secureClear(signature, sizeof(signature));
		if (!result) {
			return result;
		}

		outToken = signingInput + "." + std::string(encodedSignature.data(), signatureWritten);
		if (outToken.size() > config.maxTokenSize) {
			outToken.clear();
			return SealResult::failure(SealCode::BufferTooSmall, "token exceeds configured size limit");
		}
		return SealResult::success();
	}

	SealResult decodeParts(
	    const char *token,
	    JsonDocument *outHeader,
	    JsonDocument *outPayload,
	    TokenSegments *outSegments = nullptr
	) {
		TokenSegments segments;
		SealResult result = splitToken(token, config.maxTokenSize, segments);
		if (!result) {
			return result;
		}

		std::string headerJson;
		result = decodeStringSegment(segments.header, segments.headerLength, headerJson);
		if (!result) {
			return SealResult::failure(SealCode::InvalidHeader, result.message);
		}
		if (headerJson.size() > config.maxHeaderSize) {
			return SealResult::failure(SealCode::BufferTooSmall, "header exceeds configured size limit");
		}

		std::string payloadJson;
		result = decodeStringSegment(segments.payload, segments.payloadLength, payloadJson);
		if (!result) {
			return SealResult::failure(SealCode::InvalidPayload, result.message);
		}
		if (payloadJson.size() > config.maxPayloadSize) {
			return SealResult::failure(SealCode::BufferTooSmall, "payload exceeds configured size limit");
		}

		JsonDocument header;
		DeserializationError headerError = deserializeJson(header, headerJson);
		if (headerError) {
			return SealResult::failure(SealCode::InvalidHeader, "invalid jwt header json");
		}
		if (!header.is<JsonObject>()) {
			return SealResult::failure(SealCode::InvalidHeader, "jwt header must be an object");
		}

		JsonDocument payload;
		DeserializationError payloadError = deserializeJson(payload, payloadJson);
		if (payloadError) {
			return SealResult::failure(SealCode::InvalidPayload, "invalid jwt payload json");
		}
		if (!payload.is<JsonObject>()) {
			return SealResult::failure(SealCode::InvalidPayload, "jwt payload must be an object");
		}

		if (outHeader != nullptr) {
			outHeader->clear();
			outHeader->set(header.as<JsonObjectConst>());
		}
		if (outPayload != nullptr) {
			outPayload->clear();
			outPayload->set(payload.as<JsonObjectConst>());
		}
		if (outSegments != nullptr) {
			*outSegments = segments;
		}
		return SealResult::success();
	}

	SealResult verifyToken(
	    const char *token,
	    const char *secret,
	    const SealVerifyOptions &options,
	    JsonDocument &outPayload
	) {
		if (lifecycle != SealLifecycle::Running) {
			return resultForLifecycle(lifecycle);
		}
		if (isEmpty(secret)) {
			return SealResult::failure(SealCode::InvalidArgument, "secret is required");
		}

		JsonDocument header;
		JsonDocument payload;
		TokenSegments segments;
		SealResult result = decodeParts(token, &header, &payload, &segments);
		if (!result) {
			return result;
		}

		JsonString alg = header["alg"].as<JsonString>();
		if (!alg) {
			return SealResult::failure(SealCode::InvalidHeader, "jwt alg is required");
		}
		if (!jsonStringEquals(alg, "HS256")) {
			return SealResult::failure(SealCode::AlgorithmMismatch, "jwt alg is not HS256");
		}
		if (segments.signatureLength == 0) {
			return SealResult::failure(SealCode::SignatureRequired, "jwt signature is required");
		}
		if (segments.signatureLength > config.maxSignatureSize) {
			return SealResult::failure(SealCode::InvalidSignature, "jwt signature is too large");
		}

		uint8_t actualSignature[seal::internal::kHs256SignatureBytes] = {0};
		size_t actualSignatureLength = 0;
		result = seal::internal::base64UrlDecode(
		    segments.signature,
		    segments.signatureLength,
		    actualSignature,
		    sizeof(actualSignature),
		    actualSignatureLength
		);
		if (!result || actualSignatureLength != sizeof(actualSignature)) {
			seal::internal::secureClear(actualSignature, sizeof(actualSignature));
			return SealResult::failure(SealCode::InvalidSignature, "invalid jwt signature");
		}

		const size_t signingInputLength =
		    segments.headerLength + 1 + segments.payloadLength;
		std::string signingInput(token, signingInputLength);
		uint8_t expectedSignature[seal::internal::kHs256SignatureBytes] = {0};
		result = seal::internal::hmacSha256(
		    reinterpret_cast<const uint8_t *>(secret),
		    cstringLength(secret),
		    reinterpret_cast<const uint8_t *>(signingInput.data()),
		    signingInput.size(),
		    expectedSignature
		);
		if (!result) {
			seal::internal::secureClear(actualSignature, sizeof(actualSignature));
			seal::internal::secureClear(expectedSignature, sizeof(expectedSignature));
			return result;
		}

		const bool signatureMatches = seal::internal::constantTimeEqual(
		    actualSignature,
		    expectedSignature,
		    sizeof(expectedSignature)
		);
		seal::internal::secureClear(actualSignature, sizeof(actualSignature));
		seal::internal::secureClear(expectedSignature, sizeof(expectedSignature));
		if (!signatureMatches) {
			return SealResult::failure(SealCode::InvalidSignature, "invalid jwt signature");
		}

		uint64_t now = 0;
		bool haveClock = false;
		auto requireClock = [&]() -> SealResult {
			if (haveClock) {
				return SealResult::success();
			}
			SealResult clockResult = readClock(&options, now);
			if (clockResult) {
				haveClock = true;
			}
			return clockResult;
		};

		if (!options.ignoreExpiration && !payload["exp"].isNull()) {
			uint64_t exp = 0;
			if (!getNumericClaim(payload, "exp", exp)) {
				return SealResult::failure(SealCode::InvalidPayload, "exp must be numeric");
			}
			result = requireClock();
			if (!result) {
				return result;
			}
			if (expiredAtOrAfter(now, exp, options.clockToleranceSeconds)) {
				return SealResult::failure(SealCode::Expired, "jwt expired");
			}
		}

		if (!options.ignoreNotBefore && !payload["nbf"].isNull()) {
			uint64_t nbf = 0;
			if (!getNumericClaim(payload, "nbf", nbf)) {
				return SealResult::failure(SealCode::InvalidPayload, "nbf must be numeric");
			}
			result = requireClock();
			if (!result) {
				return result;
			}
			if (notActiveBefore(now, nbf, options.clockToleranceSeconds)) {
				return SealResult::failure(SealCode::NotActive, "jwt not active");
			}
		}

		if (options.maxAgeSeconds > 0) {
			uint64_t iat = 0;
			if (!getNumericClaim(payload, "iat", iat)) {
				return SealResult::failure(SealCode::InvalidPayload, "iat is required for maxAge");
			}
			result = requireClock();
			if (!result) {
				return result;
			}
			if (maxAgeExceeded(now, iat, options.maxAgeSeconds, options.clockToleranceSeconds)) {
				return SealResult::failure(SealCode::Expired, "jwt maxAge exceeded");
			}
		}

		if (!stringClaimEquals(payload, "iss", options.issuer)) {
			return SealResult::failure(SealCode::IssuerMismatch, "invalid issuer");
		}
		if (!stringClaimEquals(payload, "sub", options.subject)) {
			return SealResult::failure(SealCode::SubjectMismatch, "invalid subject");
		}
		if (!stringClaimEquals(payload, "aud", options.audience)) {
			return SealResult::failure(SealCode::AudienceMismatch, "invalid audience");
		}
		if (!stringClaimEquals(payload, "jti", options.jwtid)) {
			return SealResult::failure(SealCode::JwtIdMismatch, "invalid jwt id");
		}

		outPayload.clear();
		outPayload.set(payload.as<JsonObjectConst>());
		return SealResult::success();
	}

	SealResult submitJob(SealJob *job) {
		if (job == nullptr) {
			return SealResult::failure(SealCode::AllocationFailed, "job allocation failed");
		}
		if (lifecycle != SealLifecycle::Running) {
			secureJob(job);
			delete job;
			return resultForLifecycle(lifecycle);
		}
#if defined(ESP32)
		if (!config.enableAsync || queue == nullptr) {
			secureJob(job);
			delete job;
			return SealResult::failure(SealCode::InvalidArgument, "async is disabled");
		}
		if (xQueueSend(queue, &job, 0) != pdTRUE) {
			secureJob(job);
			delete job;
			return SealResult::failure(SealCode::QueueFull, "seal async queue is full");
		}
		return SealResult::success();
#else
		secureJob(job);
		delete job;
		return SealResult::failure(SealCode::InvalidArgument, "async requires ESP32");
#endif
	}

	void secureJob(SealJob *job) {
		if (job == nullptr) {
			return;
		}
		if (!job->payloadJson.empty()) {
			seal::internal::secureClear(job->payloadJson.data(), job->payloadJson.size());
		}
		if (!job->token.empty()) {
			seal::internal::secureClear(job->token.data(), job->token.size());
		}
		if (!job->secret.empty()) {
			seal::internal::secureClear(job->secret.data(), job->secret.size());
		}
	}

#if defined(ESP32)
	static void taskEntry(void *arg) {
		static_cast<SealImpl *>(arg)->runTask();
	}

	bool shouldStopWorker() {
		SealLock lock(mutex, config.useMutex);
		return !lock || stopRequested || lifecycle != SealLifecycle::Running;
	}

	void beginCallback() {
		SealLock lock(mutex, config.useMutex);
		if (lock && callbackDepth < std::numeric_limits<uint16_t>::max()) {
			++callbackDepth;
		}
	}

	void endCallback() {
		SealLock lock(mutex, config.useMutex);
		if (lock && callbackDepth > 0) {
			--callbackDepth;
		}
	}

	void runTask() {
		while (true) {
			if (shouldStopWorker()) {
				break;
			}
			SealJob *job = nullptr;
			if (xQueueReceive(queue, &job, pdMS_TO_TICKS(50)) != pdTRUE || job == nullptr) {
				continue;
			}

			if (job->type == SealJobType::Sign) {
				JsonDocument payload;
				SealResult result = SealResult::success();
				if (deserializeJson(payload, job->payloadJson)) {
					result = SealResult::failure(SealCode::InvalidPayload, "invalid queued payload json");
				}
				SealToken token;
				if (result) {
					SealLock lock(mutex, config.useMutex);
					if (!lock) {
						result = SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
					} else {
						std::string tokenValue;
						result = buildSignedToken(payload, job->signOptions, job->secret.c_str(), tokenValue);
						if (result) {
							result = allocateToken(tokenValue, token);
						}
					}
				}
				beginCallback();
				if (job->signCallback) {
					job->signCallback(result, std::move(token));
				}
				endCallback();
			} else if (job->type == SealJobType::Verify) {
				JsonDocument payload;
				SealResult result = SealResult::success();
				{
					SealLock lock(mutex, config.useMutex);
					if (!lock) {
						result = SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
					} else {
						result =
						    verifyToken(job->token.c_str(), job->secret.c_str(), job->verifyOptions, payload);
					}
				}
				beginCallback();
				if (job->verifyCallback) {
					job->verifyCallback(result, payload);
				}
				endCallback();
			} else if (job->type == SealJobType::Decode) {
				JsonDocument payload;
				SealResult result = SealResult::success();
				{
					SealLock lock(mutex, config.useMutex);
					if (!lock) {
						result = SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
					} else if (lifecycle != SealLifecycle::Running) {
						result = resultForLifecycle(lifecycle);
					} else {
						result = decodeParts(job->token.c_str(), nullptr, &payload);
					}
				}
				beginCallback();
				if (job->decodeCallback) {
					job->decodeCallback(result, payload);
				}
				endCallback();
			}

			secureJob(job);
			delete job;
		}
		if (doneSignal != nullptr) {
			xSemaphoreGive(doneSignal);
		}
		seal::internal::task::deleteCurrentTask(taskCreatedWithCaps);
	}
#endif
};

SealToken::~SealToken() {
	clear();
}

SealToken::SealToken(SealToken &&other) noexcept {
	value = other.value;
	length = other.length;
	capacity = other.capacity;
	other.value = nullptr;
	other.length = 0;
	other.capacity = 0;
}

SealToken &SealToken::operator=(SealToken &&other) noexcept {
	if (this == &other) {
		return *this;
	}
	clear();
	value = other.value;
	length = other.length;
	capacity = other.capacity;
	other.value = nullptr;
	other.length = 0;
	other.capacity = 0;
	return *this;
}

const char *SealToken::c_str() const {
	return value != nullptr ? value : "";
}

bool SealToken::empty() const {
	return value == nullptr || length == 0;
}

void SealToken::clear() {
	if (value != nullptr) {
		seal::internal::secureClear(value, capacity);
		seal::internal::release(value);
	}
	value = nullptr;
	length = 0;
	capacity = 0;
}

Seal::Seal() : _impl(new (std::nothrow) SealImpl()) {
}

Seal::~Seal() {
	deinit();
}

SealResult Seal::init(const SealConfig &config) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle == SealLifecycle::Running) {
		return SealResult::failure(SealCode::AlreadyInitialized, "seal is already initialized");
	}
	if (_impl->lifecycle == SealLifecycle::Stopping) {
		return SealResult::failure(SealCode::Busy, "seal is stopping");
	}
	SealResult result = validateConfig(config);
	if (!result) {
		return result;
	}
	_impl->config = config;
	_impl->fixedClockTimestamp = 0;
	_impl->useFixedClockTimestamp = false;
	_impl->stopRequested = false;
	_impl->callbackDepth = 0;
	_impl->lifecycle = SealLifecycle::Running;

#if defined(ESP32)
	if (config.enableAsync) {
		_impl->queue = xQueueCreate(config.queueSize, sizeof(SealJob *));
		if (_impl->queue == nullptr) {
			_impl->lifecycle = SealLifecycle::Stopped;
			return SealResult::failure(SealCode::AllocationFailed, "seal queue allocation failed");
		}
		_impl->doneSignal = xSemaphoreCreateBinary();
		if (_impl->doneSignal == nullptr) {
			vQueueDelete(_impl->queue);
			_impl->queue = nullptr;
			_impl->lifecycle = SealLifecycle::Stopped;
			return SealResult::failure(SealCode::AllocationFailed, "seal shutdown signal allocation failed");
		}
		bool usePsramStack =
		    config.stackType == SealStackType::Psram ||
		    (config.stackType == SealStackType::Auto && config.preferPsram);
		BaseType_t created = seal::internal::task::createTask(
		    SealImpl::taskEntry,
		    "Seal",
		    config.stackSizeBytes,
		    _impl.get(),
		    config.priority,
		    &_impl->task,
		    config.coreId,
		    usePsramStack,
		    _impl->taskCreatedWithCaps
		);
		if (created != pdPASS && config.stackType == SealStackType::Auto) {
			created = seal::internal::task::createTask(
			    SealImpl::taskEntry,
			    "Seal",
			    config.stackSizeBytes,
			    _impl.get(),
			    config.priority,
			    &_impl->task,
			    config.coreId,
			    false,
			    _impl->taskCreatedWithCaps
			);
		}
		if (created != pdPASS) {
			vQueueDelete(_impl->queue);
			_impl->queue = nullptr;
			vSemaphoreDelete(_impl->doneSignal);
			_impl->doneSignal = nullptr;
			_impl->lifecycle = SealLifecycle::Stopped;
			return SealResult::failure(SealCode::AllocationFailed, "seal task creation failed");
		}
	}
#endif

	return SealResult::success();
}

SealResult Seal::deinit() {
	if (!_impl) {
		return SealResult::success();
	}
#if defined(ESP32)
	QueueHandle_t queueToDelete = nullptr;
	SemaphoreHandle_t doneSignalToDelete = nullptr;
	bool waitForWorker = false;
#endif

	{
		SealLock lock(_impl->mutex, _impl->config.useMutex);
		if (!lock) {
			return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
		}
		if (_impl->lifecycle == SealLifecycle::Stopped) {
			return SealResult::success();
		}
		if (_impl->callbackDepth > 0) {
			return SealResult::failure(SealCode::Busy, "cannot deinit seal from callback");
		}
#if defined(ESP32)
		if (_impl->task != nullptr && xTaskGetCurrentTaskHandle() == _impl->task) {
			return SealResult::failure(SealCode::Busy, "cannot deinit seal from worker task");
		}
		if (_impl->queue != nullptr && _impl->task != nullptr) {
			_impl->lifecycle = SealLifecycle::Stopping;
			_impl->stopRequested = true;
			waitForWorker = true;
		} else {
			_impl->lifecycle = SealLifecycle::Stopped;
		}
#else
		_impl->lifecycle = SealLifecycle::Stopped;
#endif
	}

#if defined(ESP32)
	if (waitForWorker) {
		if (_impl->doneSignal == nullptr ||
		    xSemaphoreTake(_impl->doneSignal, pdMS_TO_TICKS(2000)) != pdTRUE) {
			return SealResult::failure(SealCode::Busy, "seal worker did not stop");
		}

		SealLock lock(_impl->mutex, _impl->config.useMutex);
		if (!lock) {
			return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
		}
		SealJob *queued = nullptr;
		while (xQueueReceive(_impl->queue, &queued, 0) == pdTRUE) {
			_impl->secureJob(queued);
			delete queued;
		}
		queueToDelete = _impl->queue;
		doneSignalToDelete = _impl->doneSignal;
		_impl->queue = nullptr;
		_impl->doneSignal = nullptr;
		_impl->task = nullptr;
		_impl->taskCreatedWithCaps = false;
		_impl->stopRequested = false;
		_impl->lifecycle = SealLifecycle::Stopped;
	}

	if (queueToDelete != nullptr) {
		vQueueDelete(queueToDelete);
	}
	if (doneSignalToDelete != nullptr) {
		vSemaphoreDelete(doneSignalToDelete);
	}
#endif

	{
		SealLock lock(_impl->mutex, _impl->config.useMutex);
		if (!lock) {
			return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
		}
		_impl->timeProvider = nullptr;
		_impl->useFixedClockTimestamp = false;
	}
	return SealResult::success();
}

bool Seal::initialized() const {
	if (!_impl) {
		return false;
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	return lock && _impl->lifecycle == SealLifecycle::Running;
}

SealResult Seal::setTimeProvider(SealTimeProvider provider) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	_impl->timeProvider = std::move(provider);
	return SealResult::success();
}

SealResult Seal::setClockTimestamp(uint64_t epochSeconds) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	_impl->fixedClockTimestamp = epochSeconds;
	_impl->useFixedClockTimestamp = true;
	return SealResult::success();
}

SealResult Seal::clearClockTimestamp() {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	_impl->fixedClockTimestamp = 0;
	_impl->useFixedClockTimestamp = false;
	return SealResult::success();
}

SealResult Seal::sign(const JsonDocument &payload, const char *secret, SealToken &outToken) {
	return sign(payload, SealOptions(), secret, outToken);
}

SealResult Seal::sign(
    const JsonDocument &payload,
    const SealOptions &options,
    const char *secret,
    SealToken &outToken
) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	std::string token;
	SealResult result = _impl->buildSignedToken(payload, options, secret, token);
	if (!result) {
		return result;
	}
	return _impl->allocateToken(token, outToken);
}

SealResult Seal::sign(
    const JsonDocument &payload,
    const SealOptions &options,
    const char *secret,
    char *outToken,
    size_t outTokenSize,
    size_t &written
) {
	written = 0;
	if (outToken == nullptr || outTokenSize == 0) {
		return SealResult::failure(SealCode::InvalidArgument, "output token buffer is required");
	}
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	std::string token;
	SealResult result = _impl->buildSignedToken(payload, options, secret, token);
	if (!result) {
		return result;
	}
	if (outTokenSize <= token.size()) {
		return SealResult::failure(SealCode::BufferTooSmall, "output token buffer too small");
	}
	std::memcpy(outToken, token.c_str(), token.size() + 1);
	written = token.size();
	return SealResult::success();
}

SealResult Seal::verify(const char *token, const char *secret, JsonDocument &outPayload) {
	return verify(token, secret, SealVerifyOptions(), outPayload);
}

SealResult Seal::verify(
    const char *token,
    const char *secret,
    const SealVerifyOptions &options,
    JsonDocument &outPayload
) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	return _impl->verifyToken(token, secret, options, outPayload);
}

SealResult Seal::decode(const char *token, JsonDocument &outPayload) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	return _impl->decodeParts(token, nullptr, &outPayload);
}

SealResult Seal::decodeHeader(const char *token, JsonDocument &outHeader) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	return _impl->decodeParts(token, &outHeader, nullptr);
}

SealResult Seal::decodeComplete(
    const char *token,
    JsonDocument &outHeader,
    JsonDocument &outPayload
) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	return _impl->decodeParts(token, &outHeader, &outPayload);
}

SealResult Seal::sign(
    const JsonDocument &payload,
    const char *secret,
    SealSignCallback callback
) {
	return sign(payload, SealOptions(), secret, std::move(callback));
}

SealResult Seal::sign(
    const JsonDocument &payload,
    const SealOptions &options,
    const char *secret,
    SealSignCallback callback
) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	if (!callback) {
		return SealResult::failure(SealCode::InvalidArgument, "sign callback is required");
	}
	if (isEmpty(secret)) {
		return SealResult::failure(SealCode::InvalidArgument, "secret is required");
	}
	std::string payloadJson;
	SealResult result = serializeDocument(payload, _impl->config.maxPayloadSize, payloadJson);
	if (!result) {
		return result;
	}
	SealJob *job = new (std::nothrow) SealJob();
	if (job == nullptr) {
		return SealResult::failure(SealCode::AllocationFailed, "job allocation failed");
	}
	job->type = SealJobType::Sign;
	job->payloadJson = std::move(payloadJson);
	job->secret = secret;
	job->signOptions = options;
	job->signCallback = std::move(callback);
	return _impl->submitJob(job);
}

SealResult Seal::verify(
    const char *token,
    const char *secret,
    SealVerifyCallback callback
) {
	return verify(token, secret, SealVerifyOptions(), std::move(callback));
}

SealResult Seal::verify(
    const char *token,
    const char *secret,
    const SealVerifyOptions &options,
    SealVerifyCallback callback
) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	if (!callback) {
		return SealResult::failure(SealCode::InvalidArgument, "verify callback is required");
	}
	if (isEmpty(token) || isEmpty(secret)) {
		return SealResult::failure(SealCode::InvalidArgument, "token and secret are required");
	}
	if (std::strlen(token) > _impl->config.maxTokenSize) {
		return SealResult::failure(SealCode::BufferTooSmall, "token exceeds configured size limit");
	}
	SealJob *job = new (std::nothrow) SealJob();
	if (job == nullptr) {
		return SealResult::failure(SealCode::AllocationFailed, "job allocation failed");
	}
	job->type = SealJobType::Verify;
	job->token = token;
	job->secret = secret;
	job->verifyOptions = options;
	job->verifyCallback = std::move(callback);
	return _impl->submitJob(job);
}

SealResult Seal::decode(const char *token, SealDecodeCallback callback) {
	if (!_impl) {
		return SealResult::failure(SealCode::AllocationFailed, "seal implementation allocation failed");
	}
	SealLock lock(_impl->mutex, _impl->config.useMutex);
	if (!lock) {
		return SealResult::failure(SealCode::InternalError, "seal mutex lock failed");
	}
	if (_impl->lifecycle != SealLifecycle::Running) {
		return resultForLifecycle(_impl->lifecycle);
	}
	if (!callback) {
		return SealResult::failure(SealCode::InvalidArgument, "decode callback is required");
	}
	if (isEmpty(token)) {
		return SealResult::failure(SealCode::InvalidArgument, "token is required");
	}
	if (std::strlen(token) > _impl->config.maxTokenSize) {
		return SealResult::failure(SealCode::BufferTooSmall, "token exceeds configured size limit");
	}
	SealJob *job = new (std::nothrow) SealJob();
	if (job == nullptr) {
		return SealResult::failure(SealCode::AllocationFailed, "job allocation failed");
	}
	job->type = SealJobType::Decode;
	job->token = token;
	job->decodeCallback = std::move(callback);
	return _impl->submitJob(job);
}

const char *Seal::codeToString(SealCode code) const {
	switch (code) {
	case SealCode::Ok:
		return "Ok";
	case SealCode::NotInitialized:
		return "NotInitialized";
	case SealCode::AlreadyInitialized:
		return "AlreadyInitialized";
	case SealCode::InvalidArgument:
		return "InvalidArgument";
	case SealCode::InvalidToken:
		return "InvalidToken";
	case SealCode::MalformedToken:
		return "MalformedToken";
	case SealCode::InvalidHeader:
		return "InvalidHeader";
	case SealCode::InvalidPayload:
		return "InvalidPayload";
	case SealCode::InvalidSignature:
		return "InvalidSignature";
	case SealCode::SignatureRequired:
		return "SignatureRequired";
	case SealCode::UnsupportedAlgorithm:
		return "UnsupportedAlgorithm";
	case SealCode::AlgorithmMismatch:
		return "AlgorithmMismatch";
	case SealCode::Expired:
		return "Expired";
	case SealCode::NotActive:
		return "NotActive";
	case SealCode::IssuerMismatch:
		return "IssuerMismatch";
	case SealCode::SubjectMismatch:
		return "SubjectMismatch";
	case SealCode::AudienceMismatch:
		return "AudienceMismatch";
	case SealCode::JwtIdMismatch:
		return "JwtIdMismatch";
	case SealCode::ClockUnavailable:
		return "ClockUnavailable";
	case SealCode::JsonError:
		return "JsonError";
	case SealCode::CryptoError:
		return "CryptoError";
	case SealCode::AllocationFailed:
		return "AllocationFailed";
	case SealCode::BufferTooSmall:
		return "BufferTooSmall";
	case SealCode::QueueFull:
		return "QueueFull";
	case SealCode::Busy:
		return "Busy";
	case SealCode::InternalError:
		return "InternalError";
	}
	return "Unknown";
}

const char *Seal::cryptoBackendName() const {
	return seal::internal::cryptoBackendName();
}
