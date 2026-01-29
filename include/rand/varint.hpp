#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace randio::module70 {

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    Empty,
    Unterminated,
    TooLong,
    Overflow,
    NonCanonical,
};

struct DecodeOptions final {
    bool require_canonical{true};
};

[[nodiscard]] std::vector<std::uint8_t> encode_u64(std::uint64_t v);

[[nodiscard]] DecodeStatus decode_u64(std::span<const std::uint8_t> bytes,
                                     std::uint64_t& out,
                                     std::size_t& consumed,
                                     const DecodeOptions& opt);

[[nodiscard]] std::optional<std::uint64_t> decode_u64(std::span<const std::uint8_t> bytes,
                                                     std::size_t& consumed,
                                                     const DecodeOptions& opt);

}
