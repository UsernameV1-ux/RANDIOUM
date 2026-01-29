#include "rand/staking.hpp"

#include <cstdint>

namespace randio {

StakingLedger::StakingLedger(Options opt) : opt_(opt) {}

std::uint64_t StakingLedger::total_bonded() const {
    std::uint64_t sum = 0;
    for (const auto& [_, pos] : stake_) {
        if (!pos.slashed) {
            sum += pos.bonded;
        }
    }
    return sum;
}

std::uint64_t StakingLedger::bonded_of(const ValidatorId& id) const {
    const auto it = stake_.find(id);
    if (it == stake_.end() || it->second.slashed) {
        return 0;
    }
    return it->second.bonded;
}

bool StakingLedger::is_slashed(const ValidatorId& id) const {
    const auto it = stake_.find(id);
    if (it == stake_.end()) {
        return false;
    }
    return it->second.slashed;
}

bool StakingLedger::bond(const ValidatorId& id, const std::uint64_t amount) {
    if (amount == 0) {
        return false;
    }
    auto& pos = stake_[id];
    if (pos.slashed) {
        return false;
    }
    const auto next = pos.bonded + amount;
    if (next < pos.bonded) {
        return false;
    }
    pos.bonded = next;
    return true;
}

bool StakingLedger::unbond(const ValidatorId& id, const std::uint64_t amount, const std::uint64_t current_height) {
    if (amount == 0) {
        return false;
    }
    auto it = stake_.find(id);
    if (it == stake_.end() || it->second.slashed) {
        return false;
    }
    auto& pos = it->second;
    if (pos.bonded < amount) {
        return false;
    }
    pos.bonded -= amount;
    const auto next_unbond = pos.unbonding + amount;
    if (next_unbond < pos.unbonding) {
        return false;
    }
    pos.unbonding = next_unbond;
    pos.unbond_ready_height = current_height + opt_.unbonding_delay_blocks;
    return true;
}

void StakingLedger::finalize_unbonding(const std::uint64_t current_height) {
    for (auto& [_, pos] : stake_) {
        if (pos.unbonding != 0 && current_height >= pos.unbond_ready_height) {
            pos.unbonding = 0;
            pos.unbond_ready_height = 0;
        }
    }
}

bool StakingLedger::slash(const ValidatorId& id) {
    return slash_amount(id).has_value();
}

std::optional<std::uint64_t> StakingLedger::slash_amount(const ValidatorId& id) {
    auto it = stake_.find(id);
    if (it == stake_.end() || it->second.slashed) {
        return std::nullopt;
    }
    const auto total = it->second.bonded + it->second.unbonding;
    if (total < it->second.bonded) {
        return std::nullopt;
    }
    it->second.bonded = 0;
    it->second.unbonding = 0;
    it->second.unbond_ready_height = 0;
    it->second.slashed = true;
    return total;
}

}
