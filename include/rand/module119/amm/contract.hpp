#pragma once

#include <vector>

#include "rand/sha256.hpp"

namespace randio::module119::amm {

[[nodiscard]] crypto::Hash256 amm119_marker_hash();

[[nodiscard]] std::vector<std::uint8_t> amm119_marker_code();

[[nodiscard]] bool is_amm119_contract(const std::vector<std::uint8_t>& code);

}
