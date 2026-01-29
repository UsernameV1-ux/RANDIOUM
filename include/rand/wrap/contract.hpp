#pragma once

#include <vector>

#include "rand/sha256.hpp"

#include "rand/wrap/asset.hpp"

namespace randio::module116 {

[[nodiscard]] crypto::Hash256 wrap116_marker_hash();

[[nodiscard]] std::vector<std::uint8_t> wrap116_marker_code();

[[nodiscard]] bool is_wrap116_contract(const std::vector<std::uint8_t>& code);

[[nodiscard]] crypto::Hash256 wrap116_contract_address(const WrappedAssetId& asset);

}
