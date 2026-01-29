#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

#include "rand/block.hpp"

namespace randio {

struct ValidationOptions final {
    std::size_t max_tx_payload_bytes{1024 * 1024};
    std::size_t max_block_txs{10000};
    std::uint32_t max_tx_version{(std::numeric_limits<std::uint32_t>::max)()};
};

bool validate_tx(const Transaction& tx, const ValidationOptions& opt);
bool validate_block(const Block& b, const ValidationOptions& opt);

}
