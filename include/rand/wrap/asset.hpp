#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "rand/sha256.hpp"

namespace randio::module116 {

struct WrappedAssetId final {
    crypto::Hash256 id{};

    [[nodiscard]] bool operator==(const WrappedAssetId& o) const noexcept {
        return id == o.id;
    }

    [[nodiscard]] bool operator<(const WrappedAssetId& o) const noexcept {
        return id < o.id;
    }
};

[[nodiscard]] WrappedAssetId canonical_wrapped_asset_id(std::string_view chain_name,
                                                       std::string_view symbol,
                                                       std::uint32_t decimals);

}
