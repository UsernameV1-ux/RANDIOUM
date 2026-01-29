#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace randio::crypto {

using Hash256 = std::array<std::uint8_t, 32>;

Hash256 sha256(std::span<const std::uint8_t> data);
Hash256 sha256(std::string_view text);

Hash256 sha256_2x32(const Hash256& left, const Hash256& right);

std::string to_hex(const Hash256& h);

}
