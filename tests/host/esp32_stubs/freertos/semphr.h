#pragma once

#include "FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

SemaphoreHandle_t xSemaphoreCreateRecursiveMutex();
SemaphoreHandle_t xSemaphoreCreateBinary();
SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *controlBlock);
SemaphoreHandle_t xSemaphoreCreateRecursiveMutexStatic(StaticSemaphore_t *controlBlock);
SemaphoreHandle_t xSemaphoreCreateBinaryStatic(StaticSemaphore_t *controlBlock);
void vSemaphoreDelete(SemaphoreHandle_t semaphore);
BaseType_t xSemaphoreTakeRecursive(SemaphoreHandle_t semaphore, TickType_t ticksToWait);
BaseType_t xSemaphoreGiveRecursive(SemaphoreHandle_t semaphore);
BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticksToWait);
BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore);
BaseType_t xSemaphoreTakeFromISR(SemaphoreHandle_t semaphore, BaseType_t *higherPriorityTaskWoken);
BaseType_t xSemaphoreGiveFromISR(SemaphoreHandle_t semaphore, BaseType_t *higherPriorityTaskWoken);

#ifdef __cplusplus
}
#endif
