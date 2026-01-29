#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "rand/mempool.hpp"
#include "rand/state.hpp"
#include "rand/tx.hpp"

namespace randio {

struct ReadWriteSet final {
    std::vector<std::string> reads;
    std::vector<std::string> writes;
};

struct ScheduledTx final {
    Transaction tx{};
    crypto::Hash256 id{};
    std::uint64_t compute{0};
    ReadWriteSet rw{};
};

struct Batch final {
    std::vector<ScheduledTx> txs;
    std::vector<ScheduledTx> rejected;
};

struct ExecutionGroup final {
    std::vector<ScheduledTx> txs;
};

struct ExecutionPlan final {
    std::vector<ExecutionGroup> groups;
    std::vector<ScheduledTx> rejected;
};

struct ExecutionResult final {
    enum class TxStatus : std::uint8_t {
        Applied = 0,
        Aborted = 1,
        Rejected = 2,
    };

    enum class ReasonCode : std::uint8_t {
        Ok = 0,
        Aborted = 1,
        Retryable = 2,
        Rejected = 3,
        Invalid = 4,
    };

    struct TxResult final {
        crypto::Hash256 id{};
        TxStatus status{TxStatus::Rejected};
        ReasonCode reason{ReasonCode::Rejected};
        std::uint64_t fee_charged{0};
        std::uint64_t gas_used{0};
    };

    struct DeltaSummary final {
        std::size_t accounts{0};
        std::size_t codes{0};
        std::size_t storage{0};
        std::size_t meta{0};

        std::vector<std::string> account_keys;
        std::vector<std::string> code_keys;
        std::vector<std::string> storage_keys;
        std::vector<std::string> meta_keys;
    };

    std::vector<crypto::Hash256> applied;
    std::vector<crypto::Hash256> aborted;
    std::vector<crypto::Hash256> rejected;
    crypto::Hash256 state_root{};

    std::vector<TxResult> tx_results;
    DeltaSummary delta;
};

class TransactionScheduler final {
public:
    struct Options final {
        std::size_t max_batch_txs{1000};
        std::size_t max_batch_bytes{4 * 1024 * 1024};
        std::uint64_t max_account_compute_per_batch{(std::numeric_limits<std::uint64_t>::max)()};
    };

    explicit TransactionScheduler(Options opt);

    [[nodiscard]] Batch build_batch(const Mempool& mempool) const;

private:
    Options opt_{};
};

class ExecutionPlanner final {
public:
    [[nodiscard]] static ExecutionPlan plan(const Batch& b);

private:
    [[nodiscard]] static bool conflicts(const ReadWriteSet& a, const ReadWriteSet& b);
};

class DeterministicExecutor final {
public:
    struct Options final {
        std::size_t parallelism{1};
    };

    explicit DeterministicExecutor(Options opt);

    [[nodiscard]] ExecutionResult execute(GlobalState& state, const ExecutionPlan& plan, std::uint64_t current_height) const;

    [[nodiscard]] ExecutionResult execute(GlobalState& state, const ExecutionPlan& plan) const {
        return execute(state, plan, 0);
    }

    [[nodiscard]] static std::optional<Transfer> decode_transfer(const Transaction& tx);
    [[nodiscard]] static std::optional<ReadWriteSet> rwset_for_tx(const Transaction& tx);
    [[nodiscard]] static std::uint64_t compute_for_tx(const Transaction& tx);

private:
    Options opt_{};

    struct AccountChange final {
        std::string id;
        std::optional<Account> next;
    };

    struct TxEffect final {
        crypto::Hash256 id{};
        bool ok{false};
        bool retryable{false};
        std::uint64_t fee{0};
        std::uint64_t fee_burn{0};
        std::uint64_t fee_tip{0};
        std::uint64_t gas_used{0};
        std::vector<std::string> read_ids;
        std::vector<AccountChange> changes;
        std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> code_changes;
        std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    };

    [[nodiscard]] static bool same_account_opt(const std::optional<Account>& a, const std::optional<Account>& b);
};

}
