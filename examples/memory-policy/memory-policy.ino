#include <Arduino.h>
#include <ArduinoJson.h>
#include <Seal.h>

Seal seal;

void setup() {
	Serial.begin(115200);

	SealConfig config;
	config.memory.allocation = Strata::Placement::PreferExternal;
	config.memory.taskStack = Strata::Placement::Internal;

	SealResult result = seal.init(config);
	if (!result) {
		Serial.printf("Seal init failed: %s\n", result.message);
		return;
	}

	JsonDocument payload;
	payload["deviceId"] = "panel-01";

	SealOptions options;
	options.noTimestamp = true;

	SealToken token;
	result = seal.sign(payload, options, "super-secret", token);
	if (!result) {
		Serial.printf("Seal sign failed: %s\n", result.message);
		return;
	}

	Serial.println(token.c_str());
}

void loop() {
	delay(1000);
}
