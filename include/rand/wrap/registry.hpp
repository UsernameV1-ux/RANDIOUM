#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "rand/wrap/asset.hpp"

namespace randio::module116 {

enum class AssetStatus : std::uint8_t {
    Active = 1,
    Disabled = 2,
};

struct AssetInfo final {
    std::string symbol;
    std::uint32_t decimals{0};
    std::string origin_chain;
    std::string origin_asset;
    AssetStatus status{AssetStatus::Active};
};

[[nodiscard]] std::vector<std::uint8_t> encode_asset_info(const AssetInfo& a);

[[nodiscard]] std::optional<AssetInfo> decode_asset_info(std::span<const std::uint8_t> bytes);

}
