#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>

namespace randio::cfg {

struct Config final {
    std::filesystem::path data_dir{};

    std::string chain_id{"moonrand-devnet"};
    std::uint32_t chain_magic{0x52414E44u};
    std::uint32_t p2p_port{30300};
    std::uint32_t rpc_port{8545};

    std::uint32_t feature_flags{0};
    std::uint64_t reward_per_block{0};

    std::string node_mode{"full"};
    std::string node_id{};

    std::uint32_t storage_schema_version{1};
    std::uint32_t max_tx_version{0};

    bool exec_cache_enabled{false};
    std::uint64_t exec_cache_max_entries{100000};
    std::uint64_t exec_cache_max_bytes{64ULL * 1024ULL * 1024ULL};

    std::uint64_t run_ticks{1};

    std::string log_format{"jsonl"};
};

struct LoadResult final {
    Config cfg;
    std::unordered_map<std::string, std::string> errors{};
};

[[nodiscard]] Config defaults();

[[nodiscard]] std::vector<std::string_view> keys();
[[nodiscard]] std::optional<std::string_view> describe(std::string_view key);
[[nodiscard]] std::string print_defaults_json();

[[nodiscard]] std::optional<std::string> read_file_text(const std::filesystem::path& p);

[[nodiscard]] std::optional<std::unordered_map<std::string, std::string>> parse_strict_json_object(std::string_view text);

[[nodiscard]] LoadResult merge_and_validate(const Config& base,
                                           const std::optional<Config>& file_cfg,
                                           const std::optional<Config>& cli_overrides);

[[nodiscard]] LoadResult load(const std::optional<std::filesystem::path>& config_path,
                             const std::optional<Config>& cli_overrides);

}
