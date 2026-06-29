# Getting Started

Include Seal and ArduinoJson:

```cpp
#include <ArduinoJson.h>
#include <Seal.h>
```

Create and initialize one Seal instance:

```cpp
Seal seal;

void setup() {
	SealResult result = seal.init();
	if (!result) {
		Serial.println(result.message);
	}
}
```

Sign a payload:

```cpp
JsonDocument payload;
payload["deviceId"] = "panel-01";

SealToken token;
SealResult result = seal.sign(payload, "super-secret", token);
```

Verify before trusting values:

```cpp
JsonDocument verified;
SealResult result = seal.verify(token.c_str(), "super-secret", verified);
```

Use epoch timestamps for expiration:

```cpp
SealOptions options;
options.iat = 1710000000;
options.exp = 1710604800;
```

Seal does not depend on Tempo. Any clock source can provide epoch seconds.
