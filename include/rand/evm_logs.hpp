#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rand/sha256.hpp"

namespace randio::module106 {

struct LogRecord final {
    crypto::Hash256 address{};
    std::vector<crypto::Hash256> topics{};
    std::vector<std::uint8_t> data{};
};

struct TopicFilter final {
    std::optional<crypto::Hash256> address;
    std::array<std::optional<std::vector<crypto::Hash256>>, 4> topics;
};

[[nodiscard]] bool matches(const LogRecord& r, const TopicFilter& f);

struct EncodeOptions final {
    std::size_t max_topics{4};
    std::size_t max_data_bytes{256 * 1024};
};

struct DecodeOptions final {
    std::size_t max_topics{4};
    std::size_t max_data_bytes{256 * 1024};
};

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    TooShort = 1,
    SizeLimit = 2,
    Invalid = 3,
};

[[nodiscard]] std::vector<std::uint8_t> encode_log_record(const LogRecord& r, const EncodeOptions& opt);
[[nodiscard]] DecodeStatus decode_log_record(std::span<const std::uint8_t> bytes, LogRecord& out, std::size_t& consumed, const DecodeOptions& opt);

[[nodiscard]] std::vector<std::uint8_t> encode_u64_le(std::uint64_t v);
[[nodiscard]] std::optional<std::uint64_t> decode_u64_le(std::span<const std::uint8_t> bytes);

[[nodiscard]] std::string log_count_key(const crypto::Hash256& txid);
[[nodiscard]] std::string log_entry_key(const crypto::Hash256& txid, std::uint32_t idx);

}
