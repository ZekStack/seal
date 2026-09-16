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

TaskHandle_t xTaskCreateStatic(
    TaskFunction_t entry,
    const char *name,
    configSTACK_DEPTH_TYPE stackDepth,
    void *arg,
    UBaseType_t priority,
    StackType_t *stackStorage,
    StaticTask_t *controlBlock
);

TaskHandle_t xTaskCreateStaticPinnedToCore(
    TaskFunction_t entry,
    const char *name,
    configSTACK_DEPTH_TYPE stackDepth,
    void *arg,
    UBaseType_t priority,
    StackType_t *stackStorage,
    StaticTask_t *controlBlock,
    BaseType_t coreId
);

TaskHandle_t xTaskGetCurrentTaskHandle();
UBaseType_t uxTaskGetStackHighWaterMark(TaskHandle_t task);
void vTaskDelete(TaskHandle_t task);
void vTaskSuspend(TaskHandle_t task);
void vTaskDelay(TickType_t ticks);

#ifdef __cplusplus
}
#endif
