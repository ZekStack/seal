#include <strata/internal/Platform.h>

#include <cstdlib>
#include <limits>

namespace Strata::Internal {
namespace {

void *allocateAligned(std::size_t sizeBytes, std::size_t alignment) noexcept {
	if (alignment <= alignof(std::max_align_t)) {
		return std::malloc(sizeBytes);
	}
	if (sizeBytes > std::numeric_limits<std::size_t>::max() - (alignment - 1)) {
		return nullptr;
	}
	const std::size_t rounded = (sizeBytes + alignment - 1) & ~(alignment - 1);
	return std::aligned_alloc(alignment, rounded);
}

} // namespace

PlatformKind platformKind() noexcept {
	return PlatformKind::Esp32;
}

const char *platformName() noexcept {
	return "seal-host-esp32";
}

void *allocate(
    std::size_t sizeBytes,
    std::size_t alignment,
    Placement placement,
    Capability capabilities
) noexcept {
	if (!validPlacement(placement) || capabilities != Capability::None) {
		return nullptr;
	}
	return allocateAligned(sizeBytes, alignment);
}

void *calloc(std::size_t count, std::size_t sizeBytes, Placement placement) noexcept {
	if (!validPlacement(placement)) {
		return nullptr;
	}
	return std::calloc(count, sizeBytes);
}

void *reallocate(void *ptr, std::size_t newSizeBytes, Placement placement) noexcept {
	if (!validPlacement(placement)) {
		return nullptr;
	}
	return std::realloc(ptr, newSizeBytes);
}

void free(void *ptr) noexcept {
	std::free(ptr);
}

Region regionOf(const void *ptr) noexcept {
	return ptr != nullptr ? Region::Internal : Region::Unknown;
}

bool supports(Placement placement) noexcept {
	return validPlacement(placement);
}

bool supports(Region region) noexcept {
	return region == Region::Internal || region == Region::External;
}

bool supports(Capability capabilities) noexcept {
	return capabilities == Capability::None;
}

MemoryStats memoryStats(Region) noexcept {
	return {};
}

} // namespace Strata::Internal
