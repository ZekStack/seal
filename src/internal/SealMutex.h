#pragma once

#if defined(ESP32)
#include <strata/freertos/Mutex.h>
#endif

class SealMutex {
  public:
	SealMutex() noexcept {
#if defined(ESP32)
		_mutex = Strata::FreeRTOS::RecursiveMutex::create();
#endif
	}

	SealMutex(const SealMutex &) = delete;
	SealMutex &operator=(const SealMutex &) = delete;

	bool valid() const noexcept {
#if defined(ESP32)
		return _mutex.valid();
#else
		return true;
#endif
	}

	bool lock() noexcept {
#if defined(ESP32)
		return _mutex.lock();
#else
		return true;
#endif
	}

	void unlock() noexcept {
#if defined(ESP32)
		_mutex.unlock();
#endif
	}

  private:
#if defined(ESP32)
	Strata::FreeRTOS::RecursiveMutex _mutex;
#endif
};

class SealLock {
  public:
	SealLock(SealMutex &mutex, bool enabled) noexcept
	    : _mutex(mutex), _enabled(enabled), _locked(!enabled || mutex.lock()) {
	}

	~SealLock() {
		if (_locked && _enabled) {
			_mutex.unlock();
		}
	}

	SealLock(const SealLock &) = delete;
	SealLock &operator=(const SealLock &) = delete;

	explicit operator bool() const noexcept {
		return _locked;
	}

  private:
	SealMutex &_mutex;
	bool _enabled = true;
	bool _locked = false;
};
