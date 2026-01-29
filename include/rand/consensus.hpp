#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "rand/sha256.hpp"
#include "rand/staking.hpp"
#include "rand/validator.hpp"

namespace randio {

using BlockId = crypto::Hash256;

struct Proposal final {
    std::uint64_t height{0};
    std::uint64_t round{0};
    BlockId parent{};
    crypto::Hash256 state_root{};
    ValidatorId proposer;
};

struct Vote final {
    std::uint64_t round{0};
    BlockId block{};
    ValidatorId voter;
    crypto::Hash256 signature{};
};

struct QuorumCert final {
    std::uint64_t round{0};
    BlockId block{};
    std::vector<ValidatorId> voters;
};

struct ConsensusBlock final {
    Proposal prop{};
    BlockId id{};
    std::optional<QuorumCert> qc;
};

class ConsensusCore final {
public:
    struct Options final {
        std::uint64_t quorum_numerator{2};
        std::uint64_t quorum_denominator{3};
        std::uint64_t partition_round_timeout{5};

        std::function<bool()> is_halted{};

        std::uint64_t block_reward{0};

        std::function<bool(const StakingLedger&,
                           const ValidatorId& proposer,
                           const std::vector<ValidatorId>& voters,
                           std::uint64_t reward,
                           std::uint64_t height)>
            on_reward{};

        std::function<bool(const ValidatorId& offender, std::uint64_t slash_amount)> on_slash{};
    };

    ConsensusCore(Options opt,
                  ValidatorId self_id,
                  ValidatorStore keys,
                  StakingLedger staking,
                  crypto::Hash256 chain_seed);

    [[nodiscard]] ValidatorId leader_for_round(std::uint64_t round) const;

    [[nodiscard]] Proposal make_proposal(std::uint64_t round, const crypto::Hash256& state_root);

    [[nodiscard]] std::optional<Vote> make_vote(const Proposal& p);

    void on_proposal(const Proposal& p);
    void on_vote(const Vote& v);

    [[nodiscard]] std::optional<QuorumCert> high_qc() const;
    [[nodiscard]] std::optional<ConsensusBlock> committed() const;

    [[nodiscard]] bool partitioned(std::uint64_t current_round) const;
    [[nodiscard]] bool recover_if_partitioned(std::uint64_t current_round);

    [[nodiscard]] bool is_slashed(const ValidatorId& id) const;
    [[nodiscard]] bool invalid() const;

private:
    Options opt_{};
    ValidatorId self_id_;
    ValidatorStore keys_;
    StakingLedger staking_;
    crypto::Hash256 chain_seed_{};

    std::unordered_map<std::string, ConsensusBlock> blocks_{};
    std::optional<QuorumCert> high_qc_;
    std::optional<ConsensusBlock> committed_;

    std::unordered_map<std::uint64_t, std::unordered_map<ValidatorId, BlockId>> votes_by_round_{};
    std::unordered_map<std::string, std::unordered_map<ValidatorId, crypto::Hash256>> sigs_by_block_{};

    std::uint64_t last_progress_round_{0};
    bool invalid_{false};
    std::uint64_t last_rewarded_height_{0};

    [[nodiscard]] BlockId proposal_id_(const Proposal& p) const;
    [[nodiscard]] crypto::Hash256 vote_digest_(const Vote& v) const;

    void try_form_qc_(const BlockId& bid, std::uint64_t round);
    void try_commit_();

    [[nodiscard]] std::uint64_t quorum_threshold_() const;

    static std::string id_key(const crypto::Hash256& h);
};

}
