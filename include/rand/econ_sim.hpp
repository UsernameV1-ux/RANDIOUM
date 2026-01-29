#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "rand/exec_engine.hpp"
#include "rand/mempool.hpp"
#include "rand/sha256.hpp"
#include "rand/staking.hpp"
#include "rand/state.hpp"
#include "rand/validator.hpp"

namespace randio::econ {

enum class ScenarioKind : std::uint32_t {
    FeeSpamCongestion = 1,
    StakeRotationAbuse = 2,
    SlashingGriefing = 3,
    ValidatorCartel = 4,
    RewardExtractionFeeManipulation = 5,
    NetworkPartitionRecovery = 6,
};

struct EconomicSimOptions final {
    std::uint64_t seed{1};
    std::uint64_t blocks{1000};

    std::uint64_t max_supply{1000000};
    std::uint64_t block_reward{5};

    std::size_t validator_count{10};
    std::size_t attacker_count{3};

    std::size_t txs_per_block{50};
    std::size_t spam_txs_per_block{500};
    std::size_t max_payload_bytes{256};

    std::uint64_t min_fee{1};
    std::uint64_t max_fee{250};

    Mempool::Options mempool{};
    TransactionScheduler::Options scheduler{};
    DeterministicExecutor::Options executor{};
    StakingLedger::Options staking{};
};

struct EconomicSimBlockMetrics final {
    std::uint64_t height{0};
    bool committed{false};
    ValidatorId proposer{};

    std::size_t mempool_txs{0};
    std::size_t mempool_bytes{0};

    std::size_t applied_txs{0};
    std::size_t aborted_txs{0};

    std::uint64_t minted_total{0};
    std::uint64_t burned_total{0};
    std::uint64_t circulating_supply{0};

    std::uint64_t minted_delta{0};
    std::uint64_t burned_delta{0};
};

struct EconomicSimSummary final {
    crypto::Hash256 transcript{};

    std::uint64_t blocks{0};
    std::uint64_t committed_blocks{0};

    std::uint64_t minted_total{0};
    std::uint64_t burned_total{0};
    std::uint64_t circulating_supply{0};

    double max_reward_share_minus_stake_share{0.0};
};

struct EconomicSimResult final {
    std::vector<EconomicSimBlockMetrics> blocks;
    EconomicSimSummary summary;
};

class EconomicSim final {
public:
    explicit EconomicSim(EconomicSimOptions opt);

    [[nodiscard]] EconomicSimResult run(const std::filesystem::path& data_dir, ScenarioKind scenario) const;

private:
    EconomicSimOptions opt_{};
};

}
