#include <Arduino.h>
#include <ArduinoJson.h>
#include <Seal.h>

Seal seal;

void setup() {
	Serial.begin(115200);
	seal.init();

	JsonDocument payload;
	payload["deviceId"] = "esp32-panel-01";

	SealToken token;
	SealResult result = seal.sign(payload, "super-secret", token);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	JsonDocument verified;
	result = seal.verify(token.c_str(), "super-secret", verified);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	Serial.println(verified["deviceId"].as<const char *>());
}

void loop() {
	delay(1000);
}
