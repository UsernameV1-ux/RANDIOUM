#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "rand/sha256.hpp"

namespace randio::module72 {

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    WrongLength,
    BadHex,
};

[[nodiscard]] std::string to_hex(const randio::crypto::Hash256& h);

[[nodiscard]] DecodeStatus from_hex(std::string_view s, randio::crypto::Hash256& out);

[[nodiscard]] std::optional<randio::crypto::Hash256> from_hex(std::string_view s);

}
