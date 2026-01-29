#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "rand/sha256.hpp"

namespace randio::module102 {

struct WorkloadReport final {
    std::string name{};
    std::uint64_t seed{0};

    std::uint64_t elapsed_ms{0};
    double tps{0.0};

    std::uint64_t applied_tx{0};
    std::uint64_t aborted_tx{0};

    std::uint64_t gas_used_total{0};
    std::uint64_t base_fee_start{0};
    std::uint64_t base_fee_end{0};
    std::uint64_t tip_pool_collected{0};

    std::uint64_t blocks_produced{0};

    crypto::Hash256 state_root_final{};

    std::uint64_t rand20_supply{0};
    crypto::Hash256 rand20_events_hash{};

    std::uint64_t randnft_supply{0};
    crypto::Hash256 randnft_events_hash{};

    std::vector<crypto::Hash256> mempool_batch_txids{};
};

struct SuiteReport final {
    std::uint64_t seed{0};
    std::filesystem::path report_path{};

    std::vector<WorkloadReport> workloads{};

    crypto::Hash256 determinism_signature{};
};

struct SuiteOptions final {
    std::uint64_t seed{77};
    bool ci_mode{true};
    std::uint64_t run_id{0};
    std::uint64_t blocks{0};
    std::string workload{};
};

[[nodiscard]] std::filesystem::path find_repo_root();
[[nodiscard]] std::filesystem::path default_report_path();

[[nodiscard]] SuiteReport run_suite(const SuiteOptions& opt);
[[nodiscard]] SuiteReport run_default_suite();

[[nodiscard]] std::string to_json(const SuiteReport& rep);
[[nodiscard]] std::string to_json_without_time_fields(const SuiteReport& rep);

[[nodiscard]] bool write_report_json(const SuiteReport& rep);

}
