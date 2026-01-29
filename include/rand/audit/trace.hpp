#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rand/sha256.hpp"

namespace randio::audit {

constexpr std::uint32_t kTraceSchemaVersion = 1;

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
    crypto::Hash256 txid{};
    TxStatus status{TxStatus::Rejected};
    ReasonCode reason{ReasonCode::Rejected};
    std::uint64_t fee_charged{0};
    std::uint64_t gas_used{0};
    std::string tx_hex;
};

struct StateDeltaSummary final {
    std::size_t accounts{0};
    std::size_t codes{0};
    std::size_t storage{0};
    std::size_t meta{0};

    std::vector<std::string> account_keys;
    std::vector<std::string> code_keys;
    std::vector<std::string> storage_keys;
    std::vector<std::string> meta_keys;
};

struct BlockTrace final {
    std::uint64_t height{0};
    crypto::Hash256 block_hash{};
    crypto::Hash256 prev_hash{};
    std::uint16_t protocol_version{0};

    crypto::Hash256 state_root_before{};
    crypto::Hash256 state_root_after{};

    std::vector<crypto::Hash256> applied_txids;
    std::vector<TxResult> tx_results;

    StateDeltaSummary delta;
};

struct EncodeOptions final {
    std::size_t max_keys_per_category{200};
    bool include_changed_keys{true};
};

[[nodiscard]] std::string encode_jsonl(const BlockTrace& t, const EncodeOptions& opt);

[[nodiscard]] std::optional<BlockTrace> decode_jsonl(std::string_view json_line);

[[nodiscard]] std::optional<std::uint64_t> extract_height(std::string_view json_line);

}
