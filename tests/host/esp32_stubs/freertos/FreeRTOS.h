#pragma once

#include <cstddef>
#include <cstdint>

typedef uint32_t TickType_t;
typedef unsigned int UBaseType_t;
typedef int BaseType_t;
typedef uint8_t StackType_t;
typedef uint32_t configSTACK_DEPTH_TYPE;
typedef void (*TaskFunction_t)(void *);

typedef struct SealHostQueue *QueueHandle_t;
typedef struct SealHostSemaphore *SemaphoreHandle_t;
typedef struct SealHostTask *TaskHandle_t;

#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define pdFAIL 0
#define portMAX_DELAY 0xffffffffu
#define tskNO_AFFINITY -1
#define pdMS_TO_TICKS(ms) ((((ms) + 99u) / 100u) == 0u ? 1u : (((ms) + 99u) / 100u))
