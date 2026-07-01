#pragma once

#include "FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

QueueHandle_t xQueueCreate(UBaseType_t length, UBaseType_t itemSize);
void vQueueDelete(QueueHandle_t queue);
BaseType_t xQueueSend(QueueHandle_t queue, const void *item, TickType_t ticksToWait);
BaseType_t xQueueReceive(QueueHandle_t queue, void *outItem, TickType_t ticksToWait);

#ifdef __cplusplus
}
#endif
