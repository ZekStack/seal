#include "SealHostFreeRtosControl.h"

#include "esp_heap_caps.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <mutex>
#include <thread>

struct SealHostQueue {
	std::mutex mutex;
	std::condition_variable cv;
	std::deque<void *> items;
	size_t capacity = 0;
	size_t itemSize = 0;
	bool deleted = false;
};

struct SealHostSemaphore {
	enum class Type : uint8_t {
		RecursiveMutex,
		Binary,
	};

	explicit SealHostSemaphore(Type semaphoreType) : type(semaphoreType) {
	}

	Type type;
	std::recursive_mutex recursiveMutex;
	std::mutex mutex;
	std::condition_variable cv;
	bool given = false;
	bool deleted = false;
};

struct SealHostTask {
	std::thread thread;
	std::atomic<bool> deleteRequested{false};
	std::atomic<bool> finished{false};
};

namespace {

SealHostTask gMainTask;
thread_local TaskHandle_t gCurrentTask = nullptr;

std::mutex gControlMutex;
std::condition_variable gControlCv;
bool gQueueReceivePaused = false;
bool gDoneSignalStalled = false;
uint32_t gBinarySemaphoreWaiters = 0;
std::atomic<uint32_t> gQueueDeleteCount{0};
std::atomic<uint32_t> gBinarySemaphoreDeleteCount{0};

std::chrono::milliseconds ticksToDuration(TickType_t ticks) {
	return std::chrono::milliseconds(ticks);
}

} // namespace

namespace seal::host::freertos {

void reset() {
	std::lock_guard<std::mutex> lock(gControlMutex);
	gQueueReceivePaused = false;
	gDoneSignalStalled = false;
	gBinarySemaphoreWaiters = 0;
	gQueueDeleteCount = 0;
	gBinarySemaphoreDeleteCount = 0;
	gControlCv.notify_all();
}

void setQueueReceivePaused(bool paused) {
	std::lock_guard<std::mutex> lock(gControlMutex);
	gQueueReceivePaused = paused;
	gControlCv.notify_all();
}

void setDoneSignalStalled(bool stalled) {
	std::lock_guard<std::mutex> lock(gControlMutex);
	gDoneSignalStalled = stalled;
	gControlCv.notify_all();
}

bool waitForBinarySemaphoreWaiter(uint32_t timeoutMs) {
	std::unique_lock<std::mutex> lock(gControlMutex);
	return gControlCv.wait_for(lock, std::chrono::milliseconds(timeoutMs), [] {
		return gBinarySemaphoreWaiters > 0;
	});
}

uint32_t queueDeleteCount() {
	return gQueueDeleteCount.load();
}

uint32_t binarySemaphoreDeleteCount() {
	return gBinarySemaphoreDeleteCount.load();
}

} // namespace seal::host::freertos

extern "C" {

size_t heap_caps_get_total_size(unsigned int) {
	return 0;
}

void *heap_caps_malloc(size_t size, unsigned int) {
	return std::malloc(size);
}

void heap_caps_free(void *ptr) {
	std::free(ptr);
}

QueueHandle_t xQueueCreate(UBaseType_t length, UBaseType_t itemSize) {
	auto *queue = new (std::nothrow) SealHostQueue();
	if (queue == nullptr) {
		return nullptr;
	}
	queue->capacity = length;
	queue->itemSize = itemSize;
	return queue;
}

void vQueueDelete(QueueHandle_t queue) {
	if (queue == nullptr) {
		return;
	}
	{
		std::lock_guard<std::mutex> lock(queue->mutex);
		queue->deleted = true;
		queue->items.clear();
	}
	queue->cv.notify_all();
	++gQueueDeleteCount;
	delete queue;
}

BaseType_t xQueueSend(QueueHandle_t queue, const void *item, TickType_t) {
	if (queue == nullptr || item == nullptr) {
		return pdFALSE;
	}
	std::lock_guard<std::mutex> lock(queue->mutex);
	if (queue->deleted || queue->items.size() >= queue->capacity) {
		return pdFALSE;
	}
	queue->items.push_back(*static_cast<void *const *>(item));
	queue->cv.notify_one();
	return pdTRUE;
}

BaseType_t xQueueReceive(QueueHandle_t queue, void *outItem, TickType_t ticksToWait) {
	if (queue == nullptr || outItem == nullptr) {
		return pdFALSE;
	}
	if (ticksToWait != 0) {
		std::unique_lock<std::mutex> controlLock(gControlMutex);
		if (gQueueReceivePaused) {
			gControlCv.wait_for(controlLock, ticksToDuration(ticksToWait), [] {
				return !gQueueReceivePaused;
			});
			if (gQueueReceivePaused) {
				return pdFALSE;
			}
		}
	}

	std::unique_lock<std::mutex> lock(queue->mutex);
	auto hasItemOrDeleted = [&] {
		return queue->deleted || !queue->items.empty();
	};
	if (ticksToWait == 0) {
		if (!hasItemOrDeleted()) {
			return pdFALSE;
		}
	} else if (ticksToWait == portMAX_DELAY) {
		queue->cv.wait(lock, hasItemOrDeleted);
	} else if (!queue->cv.wait_for(lock, ticksToDuration(ticksToWait), hasItemOrDeleted)) {
		return pdFALSE;
	}
	if (queue->deleted || queue->items.empty()) {
		return pdFALSE;
	}
	*static_cast<void **>(outItem) = queue->items.front();
	queue->items.pop_front();
	return pdTRUE;
}

SemaphoreHandle_t xSemaphoreCreateRecursiveMutex() {
	return new (std::nothrow) SealHostSemaphore(SealHostSemaphore::Type::RecursiveMutex);
}

SemaphoreHandle_t xSemaphoreCreateBinary() {
	return new (std::nothrow) SealHostSemaphore(SealHostSemaphore::Type::Binary);
}

void vSemaphoreDelete(SemaphoreHandle_t semaphore) {
	if (semaphore == nullptr) {
		return;
	}
	if (semaphore->type == SealHostSemaphore::Type::Binary) {
		++gBinarySemaphoreDeleteCount;
	}
	{
		std::lock_guard<std::mutex> lock(semaphore->mutex);
		semaphore->deleted = true;
	}
	semaphore->cv.notify_all();
	delete semaphore;
}

BaseType_t xSemaphoreTakeRecursive(SemaphoreHandle_t semaphore, TickType_t) {
	if (semaphore == nullptr || semaphore->type != SealHostSemaphore::Type::RecursiveMutex) {
		return pdFALSE;
	}
	semaphore->recursiveMutex.lock();
	return pdTRUE;
}

void xSemaphoreGiveRecursive(SemaphoreHandle_t semaphore) {
	if (semaphore == nullptr || semaphore->type != SealHostSemaphore::Type::RecursiveMutex) {
		return;
	}
	semaphore->recursiveMutex.unlock();
}

BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticksToWait) {
	if (semaphore == nullptr || semaphore->type != SealHostSemaphore::Type::Binary) {
		return pdFALSE;
	}
	std::unique_lock<std::mutex> lock(semaphore->mutex);
	auto isGivenOrDeleted = [&] {
		return semaphore->deleted || semaphore->given;
	};
	if (ticksToWait == 0) {
		if (!isGivenOrDeleted()) {
			return pdFALSE;
		}
	} else {
		{
			std::lock_guard<std::mutex> controlLock(gControlMutex);
			++gBinarySemaphoreWaiters;
			gControlCv.notify_all();
		}
		bool woke = false;
		if (ticksToWait == portMAX_DELAY) {
			semaphore->cv.wait(lock, isGivenOrDeleted);
			woke = true;
		} else {
			woke = semaphore->cv.wait_for(lock, ticksToDuration(ticksToWait), isGivenOrDeleted);
		}
		{
			std::lock_guard<std::mutex> controlLock(gControlMutex);
			if (gBinarySemaphoreWaiters > 0) {
				--gBinarySemaphoreWaiters;
			}
			gControlCv.notify_all();
		}
		if (!woke) {
			return pdFALSE;
		}
	}
	if (semaphore->deleted || !semaphore->given) {
		return pdFALSE;
	}
	semaphore->given = false;
	return pdTRUE;
}

BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore) {
	if (semaphore == nullptr || semaphore->type != SealHostSemaphore::Type::Binary) {
		return pdFALSE;
	}
	if (xTaskGetCurrentTaskHandle() != &gMainTask) {
		std::unique_lock<std::mutex> controlLock(gControlMutex);
		gControlCv.wait(controlLock, [] {
			return !gDoneSignalStalled;
		});
	}
	{
		std::lock_guard<std::mutex> lock(semaphore->mutex);
		if (semaphore->deleted) {
			return pdFALSE;
		}
		semaphore->given = true;
	}
	semaphore->cv.notify_one();
	return pdTRUE;
}

BaseType_t xTaskCreate(
    TaskFunction_t entry,
    const char *,
    uint32_t,
    void *arg,
    UBaseType_t,
    TaskHandle_t *handle
) {
	if (entry == nullptr || handle == nullptr) {
		return pdFAIL;
	}
	auto *task = new (std::nothrow) SealHostTask();
	if (task == nullptr) {
		return pdFAIL;
	}
	task->thread = std::thread([task, entry, arg] {
		gCurrentTask = task;
		entry(arg);
		task->finished = true;
		gCurrentTask = nullptr;
	});
	task->thread.detach();
	*handle = task;
	return pdPASS;
}

BaseType_t xTaskCreatePinnedToCore(
    TaskFunction_t entry,
    const char *name,
    uint32_t stackDepth,
    void *arg,
    UBaseType_t priority,
    TaskHandle_t *handle,
    BaseType_t
) {
	return xTaskCreate(entry, name, stackDepth, arg, priority, handle);
}

TaskHandle_t xTaskGetCurrentTaskHandle() {
	if (gCurrentTask != nullptr) {
		return gCurrentTask;
	}
	return &gMainTask;
}

void vTaskDelete(TaskHandle_t task) {
	TaskHandle_t target = task == nullptr ? xTaskGetCurrentTaskHandle() : task;
	if (target != nullptr) {
		target->deleteRequested = true;
	}
}

} // extern "C"
