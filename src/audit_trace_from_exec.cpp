#include "rand/audit/trace_from_exec.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "rand/hex.hpp"
#include "rand/sha256.hpp"

namespace randio::audit {
namespace {

[[nodiscard]] std::optional<Transaction> find_tx(const crypto::Hash256& id, const std::vector<Transaction>& pool) {
    for (const auto& tx : pool) {
        if (txid(tx) == id) {
            return tx;
        }
    }
    return std::nullopt;
}

} 

BlockTrace from_execution(const std::uint64_t height,
                          const crypto::Hash256& prev_hash,
                          const crypto::Hash256& block_hash,
                          const std::uint16_t protocol_version,
                          const crypto::Hash256& state_root_before,
                          const crypto::Hash256& state_root_after,
                          const ExecutionResult& res,
                          const std::vector<Transaction>& pool_txs,
                          const BuildOptions& opt) {
    BlockTrace t;
    t.height = height;
    t.block_hash = block_hash;
    t.prev_hash = prev_hash;
    t.protocol_version = protocol_version;
    t.state_root_before = state_root_before;
    t.state_root_after = state_root_after;

    t.applied_txids = res.applied;
    std::sort(t.applied_txids.begin(), t.applied_txids.end());
    t.applied_txids.erase(std::unique(t.applied_txids.begin(), t.applied_txids.end()), t.applied_txids.end());

    t.tx_results.clear();
    t.tx_results.reserve(res.tx_results.size());

    for (const auto& rr : res.tx_results) {
        TxResult out;
        out.txid = rr.id;

        if (rr.status == ExecutionResult::TxStatus::Applied) {
            out.status = TxStatus::Applied;
            out.reason = ReasonCode::Ok;
        } else if (rr.status == ExecutionResult::TxStatus::Aborted) {
            out.status = TxStatus::Aborted;
            out.reason = (rr.reason == ExecutionResult::ReasonCode::Retryable) ? ReasonCode::Retryable : ReasonCode::Aborted;
        } else {
            out.status = TxStatus::Rejected;
            out.reason = ReasonCode::Invalid;
        }

        out.fee_charged = rr.fee_charged;
        out.gas_used = rr.gas_used;

        const auto tx = find_tx(rr.id, pool_txs);
        if (tx) {
            const auto bytes = serialize_tx(*tx);
            out.tx_hex = module66::to_hex(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
        } else {
            out.tx_hex = "";
        }

        t.tx_results.push_back(std::move(out));
    }

    std::sort(t.tx_results.begin(), t.tx_results.end(), [](const TxResult& a, const TxResult& b) { return a.txid < b.txid; });

    t.delta = StateDeltaSummary{};
    t.delta.accounts = res.delta.accounts;
    t.delta.codes = res.delta.codes;
    t.delta.storage = res.delta.storage;
    t.delta.meta = res.delta.meta;

    if (opt.include_changed_keys) {
        t.delta.account_keys = res.delta.account_keys;
        t.delta.code_keys = res.delta.code_keys;
        t.delta.storage_keys = res.delta.storage_keys;
        t.delta.meta_keys = res.delta.meta_keys;

        auto bound = [&](std::vector<std::string>& v) {
            std::sort(v.begin(), v.end());
            v.erase(std::unique(v.begin(), v.end()), v.end());
            if (v.size() > opt.max_keys_per_category) {
                v.resize(opt.max_keys_per_category);
            }
        };

        bound(t.delta.account_keys);
        bound(t.delta.code_keys);
        bound(t.delta.storage_keys);
        bound(t.delta.meta_keys);
    }

    return t;
}

}
