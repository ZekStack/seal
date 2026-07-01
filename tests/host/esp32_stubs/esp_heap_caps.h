#pragma once

#include <cstddef>

#define MALLOC_CAP_SPIRAM 0x01
#define MALLOC_CAP_8BIT 0x02

#ifdef __cplusplus
extern "C" {
#endif

size_t heap_caps_get_total_size(unsigned int caps);
void *heap_caps_malloc(size_t size, unsigned int caps);
void heap_caps_free(void *ptr);

#ifdef __cplusplus
}
#endif
