#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "rand/block.hpp"

namespace randio::module68 {

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    WrongSize,
};

[[nodiscard]] constexpr std::size_t header_size_bytes() {
    return 4 + 8 + 32 + 32 + 8 + 8;
}

[[nodiscard]] DecodeStatus decode_header(std::span<const std::uint8_t> bytes, BlockHeader& out);

[[nodiscard]] std::vector<std::uint8_t> encode_header(const BlockHeader& h);

[[nodiscard]] std::optional<BlockHeader> decode_header(std::span<const std::uint8_t> bytes);

}
