#pragma once

#include <atomic>
#include <cstdint>

namespace randio::perf {

#ifdef MOONRAND_ENABLE_PERF_COUNTERS
inline std::atomic<std::uint64_t> counter{0};

inline void reset() {
    counter.store(0, std::memory_order_relaxed);
}

inline void add(const std::uint64_t n) {
    counter.fetch_add(n, std::memory_order_relaxed);
}

[[nodiscard]] inline std::uint64_t value() {
    return counter.load(std::memory_order_relaxed);
}
#else
inline void reset() {}
inline void add(std::uint64_t) {}
[[nodiscard]] inline std::uint64_t value() {
    return 0;
}
#endif

}
