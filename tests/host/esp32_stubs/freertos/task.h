#pragma once

#include "FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

BaseType_t xTaskCreate(
    TaskFunction_t entry,
    const char *name,
    uint32_t stackDepth,
    void *arg,
    UBaseType_t priority,
    TaskHandle_t *handle
);

BaseType_t xTaskCreatePinnedToCore(
    TaskFunction_t entry,
    const char *name,
    uint32_t stackDepth,
    void *arg,
    UBaseType_t priority,
    TaskHandle_t *handle,
    BaseType_t coreId
);

TaskHandle_t xTaskGetCurrentTaskHandle();
void vTaskDelete(TaskHandle_t task);

#ifdef __cplusplus
}
#endif
