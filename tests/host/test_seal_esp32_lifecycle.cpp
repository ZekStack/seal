#include <Seal.h>

#include "SealHostFreeRtosControl.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

namespace {

constexpr const char *kSecret = "super-secret";
int failureCount = 0;

void expect(bool condition, const char *message) {
	if (condition) {
		return;
	}
	std::printf("FAIL: %s\n", message);
	++failureCount;
}

void expect(const SealResult &result, const char *message) {
	if (result) {
		return;
	}
	std::printf("FAIL: %s: %s\n", message, result.message);
	++failureCount;
}

void expectCode(const SealResult &result, SealCode code, const char *message) {
	if (result.code == code) {
		return;
	}
	std::printf("FAIL: %s: expected %u got %u (%s)\n",
	    message,
	    static_cast<unsigned>(code),
	    static_cast<unsigned>(result.code),
	    result.message);
	++failureCount;
}

SealConfig testConfig(size_t queueSize = 4) {
	SealConfig config;
	config.queueSize = queueSize;
	config.stackType = SealStackType::Internal;
	config.preferPsram = false;
	return config;
}

JsonDocument payload() {
	JsonDocument doc;
	doc["deviceId"] = "panel-01";
	return doc;
}

SealOptions noTimestampOptions() {
	SealOptions options;
	options.noTimestamp = true;
	return options;
}

bool waitUntil(const std::function<bool()> &condition, uint32_t timeoutMs = 200) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
	while (std::chrono::steady_clock::now() < deadline) {
		if (condition()) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	return condition();
}

std::string signSyncToken() {
	Seal seal;
	expect(seal.init(testConfig()), "token helper init");
	SealToken token;
	expect(seal.sign(payload(), noTimestampOptions(), kSecret, token), "token helper sign");
	std::string value = token.c_str();
	expect(seal.deinit(), "token helper deinit");
	return value;
}

void testQueueFull() {
	seal::host::freertos::reset();
	seal::host::freertos::setQueueReceivePaused(true);

	Seal seal;
	expect(seal.init(testConfig(1)), "queue full init");
	expect(seal.sign(payload(), noTimestampOptions(), kSecret, [](SealResult, SealToken) {}),
	    "first queued sign succeeds");
	expectCode(
	    seal.sign(payload(), noTimestampOptions(), kSecret, [](SealResult, SealToken) {}),
	    SealCode::QueueFull,
	    "second queued sign reports queue full"
	);

	seal::host::freertos::setQueueReceivePaused(false);
	expect(seal.deinit(), "queue full deinit");
}

void testDeinitWithQueuedJobs() {
	seal::host::freertos::reset();
	seal::host::freertos::setQueueReceivePaused(true);

	std::atomic<int> callbackCount{0};
	Seal seal;
	expect(seal.init(testConfig(2)), "queued deinit init");
	expect(seal.sign(payload(), noTimestampOptions(), kSecret, [&](SealResult, SealToken) {
		++callbackCount;
	}), "queued deinit first sign");
	expect(seal.sign(payload(), noTimestampOptions(), kSecret, [&](SealResult, SealToken) {
		++callbackCount;
	}), "queued deinit second sign");
	expect(seal.deinit(), "queued deinit succeeds");
	expect(callbackCount.load() == 0, "queued jobs discarded without callbacks");
	seal::host::freertos::setQueueReceivePaused(false);
}

void testDeinitWhileQueueFull() {
	seal::host::freertos::reset();
	seal::host::freertos::setQueueReceivePaused(true);

	Seal seal;
	expect(seal.init(testConfig(1)), "full queue deinit init");
	expect(seal.sign(payload(), noTimestampOptions(), kSecret, [](SealResult, SealToken) {}),
	    "full queue first sign");
	expectCode(
	    seal.sign(payload(), noTimestampOptions(), kSecret, [](SealResult, SealToken) {}),
	    SealCode::QueueFull,
	    "full queue second sign rejected"
	);
	expect(seal.deinit(), "deinit succeeds while queue is full");
	seal::host::freertos::setQueueReceivePaused(false);
}

void testCallbackDeinitBusy() {
	seal::host::freertos::reset();

	Seal seal;
	expect(seal.init(testConfig()), "callback deinit init");
	std::mutex mutex;
	std::condition_variable cv;
	bool callbackDone = false;
	SealCode callbackDeinitCode = SealCode::Ok;

	expect(seal.sign(payload(), noTimestampOptions(), kSecret, [&](SealResult result, SealToken) {
		expect(result, "callback sign result");
		callbackDeinitCode = seal.deinit().code;
		{
			std::lock_guard<std::mutex> lock(mutex);
			callbackDone = true;
		}
		cv.notify_one();
	}), "callback deinit async sign");

	{
		std::unique_lock<std::mutex> lock(mutex);
		expect(cv.wait_for(lock, std::chrono::milliseconds(250), [&] {
			return callbackDone;
		}), "callback deinit callback ran");
	}
	expect(callbackDeinitCode == SealCode::Busy, "callback deinit returns Busy");
	expect(seal.deinit(), "callback deinit final cleanup");
}

void testSubmitAfterStoppingAndTimeoutRetry() {
	seal::host::freertos::reset();
	const std::string token = signSyncToken();
	seal::host::freertos::setDoneSignalStalled(true);
	Seal seal;
	expect(seal.init(testConfig()), "timeout retry init");
	const uint32_t queueDeletesBefore = seal::host::freertos::queueDeleteCount();
	const uint32_t binaryDeletesBefore = seal::host::freertos::binarySemaphoreDeleteCount();

	SealResult result = seal.deinit();
	expectCode(result, SealCode::Busy, "first deinit times out");
	expect(seal::host::freertos::queueDeleteCount() == queueDeletesBefore,
	    "timeout does not delete queue handle");
	expect(seal::host::freertos::binarySemaphoreDeleteCount() == binaryDeletesBefore,
	    "timeout does not delete done signal handle");

	expectCode(
	    seal.sign(payload(), noTimestampOptions(), kSecret, [](SealResult, SealToken) {}),
	    SealCode::Busy,
	    "async submit after stopping is Busy"
	);

	SealToken syncToken;
	expectCode(
	    seal.sign(payload(), noTimestampOptions(), kSecret, syncToken),
	    SealCode::Busy,
	    "sync sign after timeout is Busy"
	);
	JsonDocument out;
	expectCode(seal.verify(token.c_str(), kSecret, out), SealCode::Busy, "sync verify after timeout is Busy");
	expectCode(seal.decode(token.c_str(), out), SealCode::Busy, "sync decode after timeout is Busy");

	seal::host::freertos::setDoneSignalStalled(false);
	expect(seal.deinit(), "deinit retry succeeds after worker exits");
}

void testSubmitWhileDeinitWaits() {
	seal::host::freertos::reset();
	seal::host::freertos::setDoneSignalStalled(true);

	Seal seal;
	expect(seal.init(testConfig()), "submit while wait init");
	std::atomic<SealCode> deinitCode{SealCode::Ok};
	std::thread waiter([&] {
		deinitCode = seal.deinit().code;
	});

	expect(seal::host::freertos::waitForBinarySemaphoreWaiter(200), "deinit waiter reached semaphore");
	expectCode(
	    seal.sign(payload(), noTimestampOptions(), kSecret, [](SealResult, SealToken) {}),
	    SealCode::Busy,
	    "async submit while deinit waits is Busy"
	);
	seal::host::freertos::setDoneSignalStalled(false);
	waiter.join();
	expect(deinitCode.load() == SealCode::Ok, "waiting deinit succeeds");
}

void testConcurrentDeinitSingleWaiter() {
	seal::host::freertos::reset();
	seal::host::freertos::setDoneSignalStalled(true);

	Seal seal;
	expect(seal.init(testConfig()), "concurrent deinit init");
	std::atomic<SealCode> firstCode{SealCode::Ok};
	std::thread first([&] {
		firstCode = seal.deinit().code;
	});

	expect(seal::host::freertos::waitForBinarySemaphoreWaiter(200), "first deinit is waiting");
	SealResult second = seal.deinit();
	expectCode(second, SealCode::Busy, "second concurrent deinit is Busy");

	seal::host::freertos::setDoneSignalStalled(false);
	first.join();
	expect(firstCode.load() == SealCode::Ok, "first deinit succeeds");
}

void testDestructorBlocksUntilWorkerStops() {
	seal::host::freertos::reset();
	seal::host::freertos::setDoneSignalStalled(true);

	auto *seal = new Seal();
	expect(seal->init(testConfig()), "destructor blocking init");
	std::atomic<bool> destroyed{false};
	std::thread destroyer([&] {
		delete seal;
		destroyed = true;
	});

	expect(seal::host::freertos::waitForBinarySemaphoreWaiter(200), "destructor waits for worker");
	std::this_thread::sleep_for(std::chrono::milliseconds(10));
	expect(!destroyed.load(), "destructor remains blocked while worker is stalled");
	seal::host::freertos::setDoneSignalStalled(false);
	destroyer.join();
	expect(destroyed.load(), "destructor completes after worker exits");
}

void testDestructorDeadlockFallbackFromCallback() {
	seal::host::freertos::reset();

	auto *seal = new Seal();
	expect(seal->init(testConfig()), "destructor callback fallback init");
	std::atomic<bool> deletedInCallback{false};
	expect(seal->sign(payload(), noTimestampOptions(), kSecret, [seal, &deletedInCallback](SealResult result, SealToken) {
		expect(result, "destructor callback sign result");
		delete seal;
		deletedInCallback = true;
	}), "destructor callback async sign");

	expect(waitUntil([&] {
		return deletedInCallback.load();
	}), "destructor fallback callback completed");
}

} // namespace

int main() {
	testQueueFull();
	testDeinitWithQueuedJobs();
	testDeinitWhileQueueFull();
	testCallbackDeinitBusy();
	testSubmitAfterStoppingAndTimeoutRetry();
	testSubmitWhileDeinitWaits();
	testConcurrentDeinitSingleWaiter();
	testDestructorBlocksUntilWorkerStops();
	testDestructorDeadlockFallbackFromCallback();

	if (failureCount != 0) {
		std::printf("%d seal ESP32 lifecycle tests failed\n", failureCount);
		return 1;
	}

	std::printf("seal ESP32 lifecycle tests passed\n");
	return 0;
}
