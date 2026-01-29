#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace randio::module66 {

[[nodiscard]] std::string to_hex(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::optional<std::vector<std::uint8_t>> from_hex(std::string_view s, std::size_t max_bytes);

}
