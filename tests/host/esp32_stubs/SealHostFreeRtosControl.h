#pragma once

#include <cstdint>

namespace seal::host::freertos {

void reset();
void setQueueReceivePaused(bool paused);
void setDoneSignalStalled(bool stalled);
bool waitForBinarySemaphoreWaiter(uint32_t timeoutMs);
uint32_t queueDeleteCount();
uint32_t binarySemaphoreDeleteCount();

} // namespace seal::host::freertos
