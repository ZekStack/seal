#pragma once

#if defined(ESP32)
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#endif

class SealMutex {
  public:
	SealMutex() {
#if defined(ESP32)
		_handle = xSemaphoreCreateRecursiveMutex();
#endif
	}

	~SealMutex() {
#if defined(ESP32)
		if (_handle != nullptr) {
			vSemaphoreDelete(_handle);
			_handle = nullptr;
		}
#endif
	}

	SealMutex(const SealMutex &) = delete;
	SealMutex &operator=(const SealMutex &) = delete;

	bool lock() {
#if defined(ESP32)
		return _handle != nullptr && xSemaphoreTakeRecursive(_handle, portMAX_DELAY) == pdTRUE;
#else
		return true;
#endif
	}

	void unlock() {
#if defined(ESP32)
		if (_handle != nullptr) {
			xSemaphoreGiveRecursive(_handle);
		}
#endif
	}

  private:
#if defined(ESP32)
	SemaphoreHandle_t _handle = nullptr;
#endif
};

class SealLock {
  public:
	SealLock(SealMutex &mutex, bool enabled)
	    : _mutex(mutex), _enabled(enabled), _locked(!enabled || mutex.lock()) {
	}

	~SealLock() {
		if (_locked && _enabled) {
			_mutex.unlock();
		}
	}

	SealLock(const SealLock &) = delete;
	SealLock &operator=(const SealLock &) = delete;

	explicit operator bool() const {
		return _locked;
	}

  private:
	SealMutex &_mutex;
	bool _enabled = true;
	bool _locked = false;
};
