#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#if defined(ESP32)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#else
using UBaseType_t = unsigned int;
using BaseType_t = int;
constexpr BaseType_t tskNO_AFFINITY = -1;
#endif

struct SealImpl;

enum class SealCode : uint8_t {
	Ok,
	NotInitialized,
	AlreadyInitialized,
	InvalidArgument,
	InvalidToken,
	MalformedToken,
	InvalidHeader,
	InvalidPayload,
	InvalidSignature,
	SignatureRequired,
	UnsupportedAlgorithm,
	AlgorithmMismatch,
	Expired,
	NotActive,
	IssuerMismatch,
	SubjectMismatch,
	AudienceMismatch,
	JwtIdMismatch,
	ClockUnavailable,
	JsonError,
	CryptoError,
	AllocationFailed,
	BufferTooSmall,
	QueueFull,
	Busy,
	InternalError,
};

enum class SealAlgorithm : uint8_t {
	HS256,
};

enum class SealStackType : uint8_t {
	Auto,
	Internal,
	Psram,
};

struct SealResult {
	SealCode code = SealCode::Ok;
	const char *message = "ok";

	explicit operator bool() const {
		return code == SealCode::Ok;
	}

	static SealResult success(const char *message = "ok") {
		SealResult result;
		result.code = SealCode::Ok;
		result.message = message;
		return result;
	}

	static SealResult failure(SealCode code, const char *message) {
		SealResult result;
		result.code = code;
		result.message = message;
		return result;
	}
};

struct SealConfig {
	size_t maxTokenSize = 4096;
	size_t maxPayloadSize = 2048;
	size_t maxHeaderSize = 512;
	size_t maxSignatureSize = 64;
	size_t queueSize = 8;
	size_t stackSizeBytes = 4096;
	UBaseType_t priority = 1;
	BaseType_t coreId = tskNO_AFFINITY;
	SealStackType stackType = SealStackType::Auto;
	bool enableAsync = true;
	bool useMutex = true;
	bool preferPsram = true;
	bool addIssuedAtByDefault = true;
};

struct SealOptions {
	SealAlgorithm algorithm = SealAlgorithm::HS256;
	uint64_t iat = 0;
	uint64_t exp = 0;
	uint64_t nbf = 0;
	const char *issuer = nullptr;
	const char *subject = nullptr;
	const char *audience = nullptr;
	const char *jwtid = nullptr;
	const char *keyid = nullptr;
	bool noTimestamp = false;
};

struct SealVerifyOptions {
	const char *issuer = nullptr;
	const char *subject = nullptr;
	const char *audience = nullptr;
	const char *jwtid = nullptr;
	bool ignoreExpiration = false;
	bool ignoreNotBefore = false;
	uint32_t clockToleranceSeconds = 0;
	uint64_t clockTimestamp = 0;
	bool useClockTimestamp = false;
	uint64_t maxAgeSeconds = 0;
};

struct SealToken {
	char *value = nullptr;
	size_t length = 0;
	size_t capacity = 0;

	SealToken() = default;
	~SealToken();

	SealToken(const SealToken &) = delete;
	SealToken &operator=(const SealToken &) = delete;

	SealToken(SealToken &&other) noexcept;
	SealToken &operator=(SealToken &&other) noexcept;

	const char *c_str() const;
	bool empty() const;
	void clear();
};

using SealTimeProvider = std::function<bool(uint64_t &epochSeconds)>;
using SealSignCallback = std::function<void(SealResult, SealToken)>;
using SealVerifyCallback = std::function<void(SealResult, JsonDocument &)>;
using SealDecodeCallback = std::function<void(SealResult, JsonDocument &)>;

class Seal {
  public:
	Seal();
	~Seal();

	Seal(const Seal &) = delete;
	Seal &operator=(const Seal &) = delete;

	SealResult init(const SealConfig &config = SealConfig());
	SealResult deinit();
	bool initialized() const;

	SealResult setTimeProvider(SealTimeProvider provider);
	SealResult setClockTimestamp(uint64_t epochSeconds);
	SealResult clearClockTimestamp();

	SealResult sign(const JsonDocument &payload, const char *secret, SealToken &outToken);
	SealResult sign(
	    const JsonDocument &payload,
	    const SealOptions &options,
	    const char *secret,
	    SealToken &outToken
	);
	SealResult sign(
	    const JsonDocument &payload,
	    const SealOptions &options,
	    const char *secret,
	    char *outToken,
	    size_t outTokenSize,
	    size_t &written
	);

	SealResult verify(const char *token, const char *secret, JsonDocument &outPayload);
	SealResult verify(
	    const char *token,
	    const char *secret,
	    const SealVerifyOptions &options,
	    JsonDocument &outPayload
	);

	SealResult decode(const char *token, JsonDocument &outPayload);
	SealResult decodeHeader(const char *token, JsonDocument &outHeader);
	SealResult decodeComplete(const char *token, JsonDocument &outHeader, JsonDocument &outPayload);

	SealResult sign(const JsonDocument &payload, const char *secret, SealSignCallback callback);
	SealResult sign(
	    const JsonDocument &payload,
	    const SealOptions &options,
	    const char *secret,
	    SealSignCallback callback
	);
	SealResult verify(const char *token, const char *secret, SealVerifyCallback callback);
	SealResult verify(
	    const char *token,
	    const char *secret,
	    const SealVerifyOptions &options,
	    SealVerifyCallback callback
	);
	SealResult decode(const char *token, SealDecodeCallback callback);

	const char *codeToString(SealCode code) const;
	const char *cryptoBackendName() const;

  private:
#if defined(ESP32)
	SealResult deinitInternal(TickType_t waitTicks, bool fromDestructor);
#endif
	std::unique_ptr<SealImpl> _impl;
};
