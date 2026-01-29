#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "rand/sha256.hpp"
#include "rand/state.hpp"

namespace randio::module119::amm {

[[nodiscard]] bool amm119_apply(GlobalState& st,
                               const std::string& caller,
                               const std::string& contract_hex,
                               const std::vector<std::uint8_t>& input,
                               const crypto::Hash256& txid,
                               std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes);

}
