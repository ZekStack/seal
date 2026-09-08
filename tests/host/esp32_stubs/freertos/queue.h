#pragma once

#include "FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

QueueHandle_t xQueueCreate(UBaseType_t length, UBaseType_t itemSize);
QueueHandle_t xQueueCreateStatic(
    UBaseType_t length,
    UBaseType_t itemSize,
    uint8_t *storage,
    StaticQueue_t *controlBlock
);
void vQueueDelete(QueueHandle_t queue);
BaseType_t xQueueSend(QueueHandle_t queue, const void *item, TickType_t ticksToWait);
BaseType_t xQueueReceive(QueueHandle_t queue, void *outItem, TickType_t ticksToWait);
BaseType_t xQueueSendFromISR(QueueHandle_t queue, const void *item, BaseType_t *higherPriorityTaskWoken);
BaseType_t xQueueReceiveFromISR(QueueHandle_t queue, void *outItem, BaseType_t *higherPriorityTaskWoken);

#ifdef __cplusplus
}
#endif
