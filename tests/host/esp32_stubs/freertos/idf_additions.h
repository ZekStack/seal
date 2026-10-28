#pragma once

#include "task.h"

#ifdef __cplusplus
extern "C" {
#endif

TaskHandle_t xTaskGetCurrentTaskHandleForCore(BaseType_t coreId);

#ifdef __cplusplus
}
#endif
