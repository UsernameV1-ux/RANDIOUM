#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "rand/sha256.hpp"

namespace randio::module115 {

using ChainId = std::uint64_t;
using TokenId = crypto::Hash256;
using AccountId = crypto::Hash256;
using MsgId = crypto::Hash256;

struct DecodeOptions final {
    std::size_t max_total_bytes{4096};
    std::size_t max_memo_bytes{256};
};

struct BridgePayload final {
    std::uint64_t amount{0};
    TokenId token_id{};
    AccountId recipient{};
    std::vector<std::uint8_t> memo{};

    [[nodiscard]] bool operator==(const BridgePayload& o) const;
};

struct BridgeMessageV2 final {
    ChainId chain_id_src{0};
    ChainId chain_id_dst{0};
    std::uint64_t nonce{0};
    std::uint64_t expiry_height{0};

    BridgePayload payload{};

    [[nodiscard]] bool operator==(const BridgeMessageV2& o) const;
};

[[nodiscard]] std::optional<std::vector<std::uint8_t>> encode_message_v2(const BridgeMessageV2& msg, const DecodeOptions& opt);

[[nodiscard]] std::optional<BridgeMessageV2> decode_message_v2(std::span<const std::uint8_t> bytes, const DecodeOptions& opt);

[[nodiscard]] MsgId message_id_v2(const BridgeMessageV2& msg, const DecodeOptions& opt);

}
