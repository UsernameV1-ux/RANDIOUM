#pragma once

#include <vector>

#include "rand/sha256.hpp"

namespace randio::module118 {

[[nodiscard]] crypto::Hash256 stable118_marker_hash();

[[nodiscard]] std::vector<std::uint8_t> stable118_marker_code();

[[nodiscard]] bool is_stable118_contract(const std::vector<std::uint8_t>& code);

}
