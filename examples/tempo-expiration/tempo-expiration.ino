#include <Arduino.h>
#include <ArduinoJson.h>
#include <Seal.h>

Seal seal;

uint64_t currentEpochSeconds() {
	return 1710000000;
}

void setup() {
	Serial.begin(115200);
	seal.init();
	seal.setTimeProvider([](uint64_t &epochSeconds) {
		epochSeconds = currentEpochSeconds();
		return true;
	});

	JsonDocument payload;
	payload["deviceId"] = "esp32-panel-01";

	SealOptions signOptions;
	signOptions.iat = currentEpochSeconds();
	signOptions.exp = currentEpochSeconds() + 3600;
	signOptions.issuer = "zek-stack";

	SealToken token;
	SealResult result = seal.sign(payload, signOptions, "super-secret", token);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	SealVerifyOptions verifyOptions;
	verifyOptions.issuer = "zek-stack";

	JsonDocument verified;
	result = seal.verify(token.c_str(), "super-secret", verifyOptions, verified);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	Serial.println(verified["deviceId"].as<const char *>());
}

void loop() {
	delay(1000);
}
