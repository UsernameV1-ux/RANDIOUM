#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "rand/sha256.hpp"
#include "rand/tx.hpp"

namespace randio {

class Mempool final {
public:
    struct Options final {
        std::size_t max_txs{100000};
        std::size_t max_total_bytes{256ULL * 1024ULL * 1024ULL};
        std::size_t shards{1};
        std::uint64_t min_fee_rate_per_byte{1};
        std::uint64_t base_fee_per_gas{0};
        std::size_t max_tx_payload_bytes{1024 * 1024};
        std::uint32_t max_tx_version{(std::numeric_limits<std::uint32_t>::max)()};
    };

    explicit Mempool(Options opt);

    [[nodiscard]] bool add(const Transaction& tx);
    [[nodiscard]] bool remove(const crypto::Hash256& id);

    [[nodiscard]] bool contains(const crypto::Hash256& id) const;
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::size_t total_bytes() const;

    [[nodiscard]] std::optional<Transaction> get_tx(const crypto::Hash256& id) const;
    [[nodiscard]] std::vector<Transaction> ordered_txs(std::size_t limit) const;
    [[nodiscard]] std::vector<crypto::Hash256> ordered_txids(std::size_t limit) const;

private:
    struct Entry final {
        Transaction tx{};
        crypto::Hash256 id{};
        std::uint64_t fee_rate_per_byte{0};
        std::uint64_t effective_fee_per_gas{0};
        std::uint64_t effective_compute_bid{0};
        std::size_t bytes{0};
    };

    struct Key final {
        bool is_v2{false};
        std::uint64_t effective_fee_per_gas{0};
        std::uint64_t effective_compute_bid{0};
        std::uint64_t fee_rate_per_byte{0};
        std::uint64_t fee{0};
        crypto::Hash256 id{};
    };

    struct KeyLess final {
        bool operator()(const Key& a, const Key& b) const;
    };

    struct Shard final {
        std::set<Key, KeyLess> order{};
        std::unordered_map<std::string, Entry> by_id{};
        std::unordered_map<std::string, Key> key_by_id{};
        std::size_t total_bytes{0};
        std::size_t total_txs{0};
    };

    Options opt_{};

    std::vector<Shard> shards_{};

    std::size_t total_bytes_{0};
    std::size_t total_txs_{0};

    static std::string id_key(const crypto::Hash256& id);
    static std::uint64_t fee_rate(const Transaction& tx, std::size_t bytes);

    [[nodiscard]] std::size_t shard_index_(const crypto::Hash256& id) const;

    [[nodiscard]] bool admit_basic_(const Transaction& tx) const;
    [[nodiscard]] bool evict_until_fit_(const Key& new_key, std::size_t new_bytes);
};

}
