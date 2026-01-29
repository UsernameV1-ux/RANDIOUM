#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace randio::module78 {

struct Request final {
    enum class Kind : std::uint8_t {
        RpcGetStatus,
        RpcGetSupply,
        RpcGetAccount,
        RpcGetTx,
        RpcSnapshot,
        ExplorerIndex,
        RpcGetBlock,
    };

    Kind kind{Kind::RpcGetStatus};
    std::string id{};
    std::string txid_hex32{};
    std::uint64_t height{0};
    std::filesystem::path out_path{};
};

struct GeneratorOptions final {
    std::uint64_t seed{1};
    std::size_t total_requests{1000};
    std::size_t page_size{16};
    std::size_t max_id_len{64};
    std::size_t max_path_len{240};
};

struct ScenarioOptions final {
    std::string name{};
    GeneratorOptions gen{};
    std::size_t concurrency{1};
};

struct ScenarioResult final {
    std::string name{};
    std::size_t requests{0};
    std::size_t ok{0};
    std::size_t failed{0};
    std::uint64_t perf_cost{0};
};

struct SuiteReport final {
    std::uint64_t seed{1};
    std::filesystem::path data_dir{};
    std::filesystem::path report_path{};
    std::vector<ScenarioResult> scenarios{};
};

[[nodiscard]] std::filesystem::path find_repo_root();

[[nodiscard]] std::filesystem::path default_report_path();

[[nodiscard]] std::filesystem::path prepare_bench_chain_data_dir(std::filesystem::path base_dir,
                                                                 std::uint64_t seed,
                                                                 std::string& out_any_txid_hex32);

[[nodiscard]] std::vector<Request> generate_schedule(const GeneratorOptions& opt,
                                                     std::string_view known_txid_hex32,
                                                     const std::filesystem::path& scratch_dir);

[[nodiscard]] ScenarioResult run_scenario(const ScenarioOptions& opt,
                                         const std::filesystem::path& data_dir,
                                         std::string_view known_txid_hex32,
                                         const std::filesystem::path& scratch_dir);

[[nodiscard]] SuiteReport run_suite(std::filesystem::path scratch_base, std::uint64_t seed);

[[nodiscard]] SuiteReport run_default_suite();

[[nodiscard]] bool write_report_json(const SuiteReport& rep);

}
