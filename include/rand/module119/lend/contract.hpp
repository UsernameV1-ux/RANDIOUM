#pragma once

#include <vector>

#include "rand/sha256.hpp"

namespace randio::module119::lend {

[[nodiscard]] crypto::Hash256 lend119_marker_hash();

[[nodiscard]] std::vector<std::uint8_t> lend119_marker_code();

[[nodiscard]] bool is_lend119_contract(const std::vector<std::uint8_t>& code);

}
