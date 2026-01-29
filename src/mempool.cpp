#include "rand/mempool.hpp"

#include "rand/perf.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <queue>
#include <string>
#include <utility>
#include <vector>

namespace randio {

Mempool::Mempool(Options opt) : opt_(opt) {
    if (opt_.shards == 0) {
        opt_.shards = 1;
    }
    shards_.resize(opt_.shards);
}

bool Mempool::KeyLess::operator()(const Key& a, const Key& b) const {
    if (a.is_v2 != b.is_v2) {
        return a.is_v2;
    }
    if (a.is_v2) {
        if (a.effective_compute_bid != b.effective_compute_bid) {
            return a.effective_compute_bid > b.effective_compute_bid;
        }
        if (a.effective_fee_per_gas != b.effective_fee_per_gas) {
            return a.effective_fee_per_gas > b.effective_fee_per_gas;
        }
        return a.id < b.id;
    }
    if (a.fee_rate_per_byte != b.fee_rate_per_byte) {
        return a.fee_rate_per_byte > b.fee_rate_per_byte;
    }
    if (a.fee != b.fee) {
        return a.fee > b.fee;
    }
    return a.id < b.id;
}

std::string Mempool::id_key(const crypto::Hash256& id) {
    return crypto::to_hex(id);
}

std::uint64_t Mempool::fee_rate(const Transaction& tx, const std::size_t bytes) {
    if (bytes == 0) {
        return 0;
    }
    const auto b = static_cast<std::uint64_t>(bytes);
    return (tx.fee + b - 1) / b;
}

static std::uint64_t max_fee_per_gas(const Transaction& tx) {
    return (tx.max_fee_per_gas != 0) ? tx.max_fee_per_gas : tx.fee;
}

static std::uint64_t effective_fee_per_gas(const Transaction& tx, const std::uint64_t base_fee_per_gas) {
    if (tx.version < 2) {
        return 0;
    }
    const auto max_fee = max_fee_per_gas(tx);
    const auto sum = (tx.priority_fee_per_gas > (std::numeric_limits<std::uint64_t>::max)() - base_fee_per_gas)
                         ? (std::numeric_limits<std::uint64_t>::max)()
                         : (base_fee_per_gas + tx.priority_fee_per_gas);
    return (max_fee < sum) ? max_fee : sum;
}

static std::uint64_t effective_compute_bid(const Transaction& tx) {
    if (tx.version < 2) {
        return 0;
    }
    if (tx.compute_limit == 0 && tx.compute_price_per_unit == 0) {
        return 0;
    }

    const auto price = (tx.compute_price_per_unit != 0) ? tx.compute_price_per_unit : tx.priority_fee_per_gas;
    const auto limit = (tx.compute_limit != 0) ? tx.compute_limit : 1;
    if (price == 0 || limit == 0) {
        return 0;
    }
    if (price > (std::numeric_limits<std::uint64_t>::max)() / limit) {
        return (std::numeric_limits<std::uint64_t>::max)();
    }
    return price * limit;
}

bool Mempool::contains(const crypto::Hash256& id) const {
    const auto si = shard_index_(id);
    const auto& sh = shards_.at(si);
    return sh.by_id.find(id_key(id)) != sh.by_id.end();
}

std::size_t Mempool::size() const {
    return total_txs_;
}

std::size_t Mempool::total_bytes() const {
    return total_bytes_;
}

std::optional<Transaction> Mempool::get_tx(const crypto::Hash256& id) const {
    const auto k = id_key(id);
    const auto si = shard_index_(id);
    const auto& sh = shards_.at(si);
    const auto it = sh.by_id.find(k);
    if (it == sh.by_id.end()) {
        return std::nullopt;
    }
    return it->second.tx;
}

std::vector<Transaction> Mempool::ordered_txs(const std::size_t limit) const {
    std::vector<Transaction> out;
    out.reserve((std::min<std::size_t>)(limit, total_txs_));

    struct Cursor final {
        std::size_t shard{0};
        std::set<Key, KeyLess>::const_iterator it;
    };

    struct CursorLess final {
        bool operator()(const Cursor& a, const Cursor& b) const {
            const auto& ka = *a.it;
            const auto& kb = *b.it;
            if (KeyLess{}(ka, kb)) {
                return false;
            }
            if (KeyLess{}(kb, ka)) {
                return true;
            }
            return a.shard > b.shard;
        }
    };

    std::priority_queue<Cursor, std::vector<Cursor>, CursorLess> pq;
    for (std::size_t si = 0; si < shards_.size(); ++si) {
        const auto& sh = shards_[si];
        if (!sh.order.empty()) {
            pq.push(Cursor{si, sh.order.begin()});
        }
    }

    while (!pq.empty() && out.size() < limit) {
        auto c = pq.top();
        pq.pop();

        const auto& k = *c.it;
        const auto& sh = shards_.at(c.shard);
        const auto ent_it = sh.by_id.find(id_key(k.id));
        if (ent_it != sh.by_id.end()) {
            out.push_back(ent_it->second.tx);
        }

        ++c.it;
        if (c.it != sh.order.end()) {
            pq.push(c);
        }
    }
    return out;
}

bool Mempool::admit_basic_(const Transaction& tx) const {
    if (tx.version > opt_.max_tx_version) {
        return false;
    }
    if (tx.payload.size() > opt_.max_tx_payload_bytes) {
        return false;
    }

    if (tx.version >= 2) {
        if (max_fee_per_gas(tx) < opt_.base_fee_per_gas) {
            return false;
        }
    }

    const auto bytes = serialize_tx(tx).size();
    const auto fr = fee_rate(tx, bytes);
    if (fr < opt_.min_fee_rate_per_byte) {
        return false;
    }
    return true;
}

bool Mempool::evict_until_fit_(const Key& new_key, const std::size_t new_bytes) {
    while ((total_txs_ + 1) > opt_.max_txs || (total_bytes_ + new_bytes) > opt_.max_total_bytes) {
        std::optional<std::size_t> worst_shard;
        std::optional<Key> worst_key;

        auto pick_worst_key = [](const std::set<Key, KeyLess>& order) -> Key {
            auto it = std::prev(order.end());
            if (!it->is_v2) {
                return *it;
            }

            const auto eff = it->effective_fee_per_gas;
            while (it != order.begin()) {
                auto prev = std::prev(it);
                if (!prev->is_v2 || prev->effective_fee_per_gas != eff) {
                    break;
                }
                it = prev;
            }
            return *it;
        };

        auto worse_for_eviction = [](const Key& a, const Key& b) -> bool {
            if (a.is_v2 != b.is_v2) {
                // Keep v1 behavior unchanged: v1 txs are worse than v2 txs.
                return !a.is_v2;
            }
            if (a.is_v2) {
                if (a.effective_fee_per_gas != b.effective_fee_per_gas) {
                    return a.effective_fee_per_gas < b.effective_fee_per_gas;
                }
                // Deterministic strict-caps semantics: evict lowest-paying v2, tie txid ascending.
                return a.id < b.id;
            }
            if (KeyLess{}(b, a)) {
                return true;
            }
            return false;
        };

        auto better_than_worst_for_admission = [](const Key& nk, const Key& wk) -> bool {
            if (wk.is_v2 != nk.is_v2) {
                return nk.is_v2;
            }
            if (nk.is_v2) {
                if (nk.effective_fee_per_gas != wk.effective_fee_per_gas) {
                    return nk.effective_fee_per_gas > wk.effective_fee_per_gas;
                }
                // If same effective fee, only admit if new txid is greater (so it won't be the first evicted).
                return nk.id > wk.id;
            }
            return KeyLess{}(nk, wk);
        };

        for (std::size_t si = 0; si < shards_.size(); ++si) {
            const auto& sh = shards_[si];
            if (sh.order.empty()) {
                continue;
            }
            const auto k = pick_worst_key(sh.order);
            if (!worst_key.has_value()) {
                worst_key = k;
                worst_shard = si;
                continue;
            }
            if (worse_for_eviction(k, *worst_key)) {
                worst_key = k;
                worst_shard = si;
                continue;
            }
            if (!worse_for_eviction(*worst_key, k) && si < *worst_shard) {
                worst_key = k;
                worst_shard = si;
            }
        }

        if (!worst_key.has_value() || !worst_shard.has_value()) {
            return false;
        }

        const auto& wk = *worst_key;
        if (!better_than_worst_for_admission(new_key, wk)) {
            return false;
        }

        auto& sh = shards_.at(*worst_shard);
        const auto worst_it = sh.order.find(wk);
        if (worst_it == sh.order.end()) {
            return false;
        }
        const auto worst_id = worst_it->id;
        const auto kstr = id_key(worst_id);
        const auto ent_it = sh.by_id.find(kstr);
        if (ent_it == sh.by_id.end()) {
            return false;
        }

        total_bytes_ -= ent_it->second.bytes;
        sh.total_bytes -= ent_it->second.bytes;
        sh.by_id.erase(ent_it);
        sh.key_by_id.erase(kstr);
        sh.order.erase(worst_it);

        total_txs_ -= 1;
        sh.total_txs -= 1;
    }
    return true;
}

std::size_t Mempool::shard_index_(const crypto::Hash256& id) const {
    const std::size_t n = (opt_.shards == 0) ? 1 : opt_.shards;
    const std::size_t x = static_cast<std::size_t>(id[0]);
    return x % n;
}

bool Mempool::add(const Transaction& tx) {
    perf::add(1);
    if (!admit_basic_(tx)) {
        return false;
    }

    Entry e;
    e.tx = tx;
    const auto id = txid(tx);
    e.id = id;

    const auto bytes_vec = serialize_tx(tx);
    e.bytes = bytes_vec.size();
    e.fee_rate_per_byte = fee_rate(tx, e.bytes);
    e.effective_fee_per_gas = effective_fee_per_gas(tx, opt_.base_fee_per_gas);
    e.effective_compute_bid = effective_compute_bid(tx);

    const auto key_str = id_key(id);
    const auto si = shard_index_(id);
    auto& sh = shards_.at(si);
    if (sh.by_id.find(key_str) != sh.by_id.end()) {
        return false;
    }

    Key k;
    k.is_v2 = tx.version >= 2;
    k.effective_fee_per_gas = e.effective_fee_per_gas;
    k.effective_compute_bid = e.effective_compute_bid;
    k.fee_rate_per_byte = e.fee_rate_per_byte;
    k.fee = tx.fee;
    k.id = id;

    if (!evict_until_fit_(k, e.bytes)) {
        return false;
    }

    sh.order.insert(k);
    sh.by_id.emplace(key_str, std::move(e));
    sh.key_by_id.emplace(key_str, k);
    total_bytes_ += sh.by_id.at(key_str).bytes;
    sh.total_bytes += sh.by_id.at(key_str).bytes;
    total_txs_ += 1;
    sh.total_txs += 1;
    return true;
}

bool Mempool::remove(const crypto::Hash256& id) {
    const auto k = id_key(id);
    const auto si = shard_index_(id);
    auto& sh = shards_.at(si);
    const auto it = sh.by_id.find(k);
    if (it == sh.by_id.end()) {
        return false;
    }

    total_bytes_ -= it->second.bytes;
    sh.total_bytes -= it->second.bytes;
    sh.by_id.erase(it);
    total_txs_ -= 1;
    sh.total_txs -= 1;

    const auto kit = sh.key_by_id.find(k);
    if (kit != sh.key_by_id.end()) {
        sh.order.erase(kit->second);
        sh.key_by_id.erase(kit);
    }

    return true;
}

std::vector<crypto::Hash256> Mempool::ordered_txids(const std::size_t limit) const {
    std::vector<crypto::Hash256> out;
    out.reserve((std::min<std::size_t>)(limit, total_txs_));

    struct Cursor final {
        std::size_t shard{0};
        std::set<Key, KeyLess>::const_iterator it;
    };

    struct CursorLess final {
        bool operator()(const Cursor& a, const Cursor& b) const {
            const auto& ka = *a.it;
            const auto& kb = *b.it;
            if (KeyLess{}(ka, kb)) {
                return false;
            }
            if (KeyLess{}(kb, ka)) {
                return true;
            }
            return a.shard > b.shard;
        }
    };

    std::priority_queue<Cursor, std::vector<Cursor>, CursorLess> pq;
    for (std::size_t si = 0; si < shards_.size(); ++si) {
        const auto& sh = shards_[si];
        if (!sh.order.empty()) {
            pq.push(Cursor{si, sh.order.begin()});
        }
    }

    while (!pq.empty() && out.size() < limit) {
        auto c = pq.top();
        pq.pop();
        out.push_back(c.it->id);
        ++c.it;
        const auto& sh = shards_.at(c.shard);
        if (c.it != sh.order.end()) {
            pq.push(c);
        }
    }
    return out;
}

}
