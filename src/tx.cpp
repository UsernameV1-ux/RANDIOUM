#include "rand/tx.hpp"

#include "rand/perf.hpp"

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

std::vector<std::uint8_t> serialize_tx(const Transaction& tx) {
    std::vector<std::uint8_t> out;
    if (tx.version >= 2) {
        if (tx.compute_limit == 0 && tx.compute_price_per_unit == 0) {
            out.reserve(4 + 8 + 8 + 8 + 4 + tx.payload.size());
        } else {
            out.reserve(4 + 8 + 8 + 8 + 8 + 8 + 4 + tx.payload.size());
        }
    } else {
        out.reserve(4 + 8 + 8 + 4 + tx.payload.size());
    }

    append_u32_le(out, tx.version);
    append_u64_le(out, tx.nonce);
    if (tx.version >= 2) {
        const auto max_fee = (tx.max_fee_per_gas != 0) ? tx.max_fee_per_gas : tx.fee;
        append_u64_le(out, max_fee);
        append_u64_le(out, tx.priority_fee_per_gas);
        if (tx.compute_limit != 0 || tx.compute_price_per_unit != 0) {
            append_u64_le(out, tx.compute_limit);
            append_u64_le(out, tx.compute_price_per_unit);
        }
    } else {
        append_u64_le(out, tx.fee);
    }
    append_u32_le(out, static_cast<std::uint32_t>(tx.payload.size()));
    out.insert(out.end(), tx.payload.begin(), tx.payload.end());

    perf::add(static_cast<std::uint64_t>(out.size()));

    return out;
}

crypto::Hash256 txid(const Transaction& tx) {
    const auto bytes = serialize_tx(tx);
    return crypto::sha256(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}

}
