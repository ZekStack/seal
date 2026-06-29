#include <Arduino.h>
#include <ArduinoJson.h>
#include <Seal.h>

Seal seal;

void setup() {
	Serial.begin(115200);

	SealResult initResult = seal.init();
	if (!initResult) {
		Serial.println(initResult.message);
		return;
	}

	JsonDocument payload;
	payload["deviceId"] = "esp32-panel-01";
	payload["role"] = "device";

	SealToken token;
	SealResult result = seal.sign(payload, "super-secret", token);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	Serial.println(token.c_str());
}

void loop() {
	delay(1000);
}
