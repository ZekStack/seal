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
	seal.sign(payload, "super-secret", token);

	JsonDocument decoded;
	SealResult result = seal.decode(token.c_str(), decoded);
	if (!result) {
		Serial.println(result.message);
		return;
	}

	serializeJsonPretty(decoded, Serial);
	Serial.println();
}

void loop() {
	delay(1000);
}
