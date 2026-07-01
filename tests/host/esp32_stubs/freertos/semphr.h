#pragma once

#include "FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

SemaphoreHandle_t xSemaphoreCreateRecursiveMutex();
SemaphoreHandle_t xSemaphoreCreateBinary();
void vSemaphoreDelete(SemaphoreHandle_t semaphore);
BaseType_t xSemaphoreTakeRecursive(SemaphoreHandle_t semaphore, TickType_t ticksToWait);
void xSemaphoreGiveRecursive(SemaphoreHandle_t semaphore);
BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticksToWait);
BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore);

#ifdef __cplusplus
}
#endif
