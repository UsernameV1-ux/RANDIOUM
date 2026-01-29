#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "rand/validator.hpp"

namespace randio {

struct StakePosition final {
    std::uint64_t bonded{0};
    std::uint64_t unbonding{0};
    std::uint64_t unbond_ready_height{0};
    bool slashed{false};
};

class StakingLedger final {
public:
    struct Options final {
        std::uint64_t unbonding_delay_blocks{100};
    };

    explicit StakingLedger(Options opt);

    [[nodiscard]] std::uint64_t total_bonded() const;
    [[nodiscard]] std::uint64_t bonded_of(const ValidatorId& id) const;
    [[nodiscard]] bool is_slashed(const ValidatorId& id) const;

    [[nodiscard]] bool bond(const ValidatorId& id, std::uint64_t amount);
    [[nodiscard]] bool unbond(const ValidatorId& id, std::uint64_t amount, std::uint64_t current_height);
    void finalize_unbonding(std::uint64_t current_height);

    [[nodiscard]] bool slash(const ValidatorId& id);
    [[nodiscard]] std::optional<std::uint64_t> slash_amount(const ValidatorId& id);

private:
    Options opt_{};
    std::unordered_map<ValidatorId, StakePosition> stake_{};
};

}
