#pragma once

#include <cstdint>
#include <span>

namespace randio::crypto {

std::uint32_t crc32_ieee(std::span<const std::uint8_t> data);

}
