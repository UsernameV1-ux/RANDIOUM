#include "rand/block.hpp"

#include "rand/perf.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace randio {
namespace {

void append_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

}

std::vector<std::uint8_t> serialize_block_header(const BlockHeader& h) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + 8 + 32 + 32 + 8 + 8);

    append_u32_le(out, h.version);
    append_u64_le(out, h.height);
    out.insert(out.end(), h.prev_block.begin(), h.prev_block.end());
    out.insert(out.end(), h.merkle_root.begin(), h.merkle_root.end());
    append_u64_le(out, h.timestamp_unix_seconds);
    append_u64_le(out, h.nonce);

    return out;
}

crypto::Hash256 block_hash(const BlockHeader& h) {
    const auto bytes = serialize_block_header(h);
    return crypto::sha256(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}

crypto::Hash256 merkle_root(const std::vector<Transaction>& txs) {
    perf::add(static_cast<std::uint64_t>(txs.size()));
    if (txs.empty()) {
        return crypto::sha256(std::string_view{});
    }

    std::vector<crypto::Hash256> layer;
    layer.reserve(txs.size());
    for (const auto& tx : txs) {
        layer.push_back(txid(tx));
    }

    std::vector<crypto::Hash256> next;
    next.reserve((layer.size() + 1) / 2);
    while (layer.size() > 1) {
        next.clear();
        next.reserve((layer.size() + 1) / 2);

        for (std::size_t i = 0; i < layer.size(); i += 2) {
            const auto& left = layer[i];
            const auto& right = (i + 1 < layer.size()) ? layer[i + 1] : layer[i];

            next.push_back(crypto::sha256_2x32(left, right));
        }

        layer.swap(next);
    }

    return layer[0];
}

}
