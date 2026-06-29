#pragma once

#include "../Seal.h"

#include <cstdlib>

#if defined(ESP32)
#include <esp_heap_caps.h>
#endif

namespace seal::internal {

inline void *allocate(size_t size, bool preferPsram) {
	if (size == 0) {
		return nullptr;
	}
#if defined(ESP32)
	if (preferPsram && heap_caps_get_total_size(MALLOC_CAP_SPIRAM) > 0) {
		void *ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
		if (ptr != nullptr) {
			return ptr;
		}
	}
	return heap_caps_malloc(size, MALLOC_CAP_8BIT);
#else
	(void)preferPsram;
	return std::malloc(size);
#endif
}

inline void release(void *ptr) {
	if (ptr == nullptr) {
		return;
	}
#if defined(ESP32)
	heap_caps_free(ptr);
#else
	std::free(ptr);
#endif
}

} // namespace seal::internal
