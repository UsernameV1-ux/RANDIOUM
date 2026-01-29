#pragma once

#include <cstdint>
#include <vector>

#include "rand/sha256.hpp"
#include "rand/tx.hpp"

namespace randio {

struct BlockHeader final {
    std::uint32_t version{1};
    std::uint64_t height{0};
    crypto::Hash256 prev_block{};
    crypto::Hash256 merkle_root{};
    std::uint64_t timestamp_unix_seconds{0};
    std::uint64_t nonce{0};
};

struct Block final {
    BlockHeader header{};
    std::vector<Transaction> transactions{};
};

std::vector<std::uint8_t> serialize_block_header(const BlockHeader& h);
crypto::Hash256 block_hash(const BlockHeader& h);
crypto::Hash256 merkle_root(const std::vector<Transaction>& txs);

}
