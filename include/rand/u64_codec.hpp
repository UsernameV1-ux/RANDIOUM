#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace randio::module73 {

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    Empty,
    BadChar,
    Overflow,
    NonCanonical,
};

struct DecodeOptions final {
    bool require_canonical{true};
};

[[nodiscard]] DecodeStatus parse_u64(std::string_view s, std::uint64_t& out, const DecodeOptions& opt);

[[nodiscard]] std::optional<std::uint64_t> parse_u64(std::string_view s, const DecodeOptions& opt);

[[nodiscard]] std::string format_u64(std::uint64_t v);

}
