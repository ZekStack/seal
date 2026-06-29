#include <Arduino.h>
#include <ArduinoJson.h>
#include <Seal.h>

Seal seal;

void setup() {
	Serial.begin(115200);
	seal.init();

	JsonDocument payload;
	payload["deviceId"] = "esp32-panel-01";

	char token[512];
	size_t written = 0;
	SealResult result =
	    seal.sign(payload, SealOptions(), "super-secret", token, sizeof(token), written);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	Serial.print("written=");
	Serial.println(written);
	Serial.println(token);
}

void loop() {
	delay(1000);
}
