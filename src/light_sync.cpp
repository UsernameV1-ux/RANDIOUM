#include "rand/light_sync.hpp"

#include "rand/block.hpp"
#include "rand/hash256_codec.hpp"

#include <algorithm>

namespace randio::module82 {

LightHeaderSync::LightHeaderSync(SyncOptions opt) : opt_(opt) {}

std::string LightHeaderSync::hex_(const crypto::Hash256& h) {
    return crypto::to_hex(h);
}

void LightHeaderSync::set_checkpoints(std::vector<Checkpoint> cps) {
    cps_ = std::move(cps);
    std::sort(cps_.begin(), cps_.end(), [](const Checkpoint& a, const Checkpoint& b) { return a.height < b.height; });
    cps_.erase(std::unique(cps_.begin(), cps_.end(), [](const Checkpoint& a, const Checkpoint& b) { return a.height == b.height; }), cps_.end());

    if (tip_hash_hex_) {
        const auto tip_hash_bytes = randio::module72::from_hex(*tip_hash_hex_);
        if (tip_hash_bytes.has_value()) {
            if (!checkpoint_allows_(*tip_hash_bytes, tip_height_)) {
                tip_hash_hex_.reset();
                tip_height_ = 0;
            }
        }
    }
}

bool LightHeaderSync::checkpoint_allows_(const crypto::Hash256& tip_hash, const std::uint64_t tip_height) const {
    if (cps_.empty()) {
        return true;
    }

    for (auto it = cps_.rbegin(); it != cps_.rend(); ++it) {
        if (it->height > tip_height) {
            continue;
        }
        const auto anc = ancestor_hash_(tip_hash, tip_height, it->height);
        if (!anc.has_value()) {
            return false;
        }
        return (*anc == it->block_hash);
    }

    return true;
}

std::optional<crypto::Hash256> LightHeaderSync::ancestor_hash_(crypto::Hash256 tip_hash,
                                                              std::uint64_t tip_height,
                                                              const std::uint64_t target_height) const {
    if (target_height > tip_height) {
        return std::nullopt;
    }

    while (tip_height > target_height) {
        const auto it = by_hash_.find(hex_(tip_hash));
        if (it == by_hash_.end()) {
            return std::nullopt;
        }
        tip_hash = it->second.parent;
        tip_height -= 1;
    }

    return tip_hash;
}

void LightHeaderSync::try_connect_(HeaderInfo& hi) {
    if (hi.connected) {
        return;
    }

    if (hi.height == 0) {
        hi.connected = true;
        hi.chain_work = 1;
        return;
    }

    const auto pit = by_hash_.find(hex_(hi.parent));
    if (pit == by_hash_.end()) {
        return;
    }

    if (!pit->second.connected) {
        return;
    }

    if (hi.header.height != pit->second.header.height + 1) {
        return;
    }

    hi.connected = true;
    hi.chain_work = pit->second.chain_work + 1;
}

void LightHeaderSync::maybe_update_tip_(const HeaderInfo& hi) {
    if (!hi.connected) {
        return;
    }

    const auto hhex = hex_(hi.hash);
    if (!checkpoint_allows_(hi.hash, hi.height)) {
        return;
    }

    if (!tip_hash_hex_) {
        tip_hash_hex_ = hhex;
        tip_height_ = hi.height;
        return;
    }

    if (hi.height > tip_height_) {
        tip_hash_hex_ = hhex;
        tip_height_ = hi.height;
        return;
    }

    if (hi.height == tip_height_) {
        if (hhex < *tip_hash_hex_) {
            tip_hash_hex_ = hhex;
            tip_height_ = hi.height;
        }
    }
}

AddStatus LightHeaderSync::add_header(const BlockHeader& h) {
    if (by_hash_.size() >= opt_.max_headers) {
        return AddStatus::TooManyHeaders;
    }

    HeaderInfo hi;
    hi.header = h;
    hi.hash = block_hash(h);
    hi.height = h.height;
    hi.parent = h.prev_block;

    const auto hhex = hex_(hi.hash);
    if (by_hash_.find(hhex) != by_hash_.end()) {
        return AddStatus::Duplicate;
    }

    by_hash_.emplace(hhex, hi);

    // Try to connect this header and any children that were waiting on it.
    // Deterministic convergence: iterate until no more progress.
    bool progress = true;
    while (progress) {
        progress = false;
        for (auto& [k, v] : by_hash_) {
            const bool before = v.connected;
            try_connect_(v);
            if (!before && v.connected) {
                progress = true;
            }
        }
    }

    // Update tip deterministically.
    for (const auto& [k, v] : by_hash_) {
        maybe_update_tip_(v);
    }

    // If tip exists but violates checkpoint due to missing ancestry, drop it.
    if (tip_hash_hex_) {
        const auto tip_hash_bytes = randio::module72::from_hex(*tip_hash_hex_);
        if (!tip_hash_bytes.has_value() || !checkpoint_allows_(*tip_hash_bytes, tip_height_)) {
            tip_hash_hex_.reset();
            tip_height_ = 0;
        }
    }

    return AddStatus::Ok;
}

std::optional<BlockHeader> LightHeaderSync::tip_header() const {
    if (!tip_hash_hex_) {
        return std::nullopt;
    }
    const auto it = by_hash_.find(*tip_hash_hex_);
    if (it == by_hash_.end()) {
        return std::nullopt;
    }
    return it->second.header;
}

std::optional<crypto::Hash256> LightHeaderSync::tip_hash() const {
    if (!tip_hash_hex_) {
        return std::nullopt;
    }
    const auto h = randio::module72::from_hex(*tip_hash_hex_);
    if (!h.has_value()) {
        return std::nullopt;
    }
    return *h;
}

std::optional<std::uint64_t> LightHeaderSync::tip_height() const {
    if (!tip_hash_hex_) {
        return std::nullopt;
    }
    return tip_height_;
}

std::optional<crypto::Hash256> LightHeaderSync::hash_at_height(const std::uint64_t height) const {
    if (!tip_hash_hex_) {
        return std::nullopt;
    }
    if (height > tip_height_) {
        return std::nullopt;
    }

    const auto tip_hash_bytes = randio::module72::from_hex(*tip_hash_hex_);
    if (!tip_hash_bytes.has_value()) {
        return std::nullopt;
    }

    return ancestor_hash_(*tip_hash_bytes, tip_height_, height);
}

}
