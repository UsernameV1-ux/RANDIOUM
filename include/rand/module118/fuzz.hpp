#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace randio::module118 {

struct FuzzResult final {
    std::uint64_t signature{0};
};

struct FuzzOptions final {
    std::size_t max_input_bytes{4096};
    std::size_t max_ops{64};
    std::size_t max_accounts{8};
    std::uint64_t seed{1};
};

[[nodiscard]] FuzzResult stable118_fuzz(std::span<const std::uint8_t> data, const FuzzOptions& opt);

}
