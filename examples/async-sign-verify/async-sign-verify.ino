#include <Arduino.h>
#include <ArduinoJson.h>
#include <Seal.h>

Seal seal;

void setup() {
	Serial.begin(115200);
	seal.init();

	JsonDocument payload;
	payload["deviceId"] = "esp32-panel-01";

	SealResult result = seal.sign(payload, "super-secret", [](SealResult signResult, SealToken token) {
		if (!signResult) {
			Serial.println(signResult.message);
			return;
		}

		Serial.println(token.c_str());

		seal.verify(token.c_str(), "super-secret", [](SealResult verifyResult, JsonDocument &verified) {
			if (!verifyResult) {
				Serial.println(verifyResult.message);
				return;
			}

			Serial.println(verified["deviceId"].as<const char *>());
		});
	});

	if (!result) {
		Serial.println(result.message);
	}
}

void loop() {
	delay(1000);
}
