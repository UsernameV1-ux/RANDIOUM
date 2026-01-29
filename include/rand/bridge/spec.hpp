#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rand/sha256.hpp"
#include "rand/storage.hpp"

namespace randio::module113 {

using ChainId = std::uint64_t;
using AccountId = crypto::Hash256;

struct BridgeMessage final {
    ChainId chain_id_src{0};
    ChainId chain_id_dst{0};
    std::uint64_t nonce{0};
    std::vector<std::uint8_t> asset_id{};
    std::uint64_t amount{0};
    AccountId sender{};
    AccountId recipient{};
    std::vector<std::uint8_t> payload{};

    [[nodiscard]] bool operator==(const BridgeMessage& o) const;
};

struct DecodeOptions final {
    std::size_t max_asset_id_bytes{256};
    std::size_t max_payload_bytes{4096};
};

[[nodiscard]] std::vector<std::uint8_t> encode_message(const BridgeMessage& msg, const DecodeOptions& opt);

[[nodiscard]] std::optional<BridgeMessage> decode_message(std::span<const std::uint8_t> bytes, const DecodeOptions& opt);

[[nodiscard]] crypto::Hash256 message_hash(const BridgeMessage& msg, const DecodeOptions& opt);

enum class FieldId : std::uint8_t {
    ChainIdSrc = 1,
    ChainIdDst = 2,
    Nonce = 3,
    AssetId = 4,
    Amount = 5,
    Sender = 6,
    Recipient = 7,
    Payload = 8,
};

struct MessageField final {
    FieldId id{FieldId::ChainIdSrc};
    std::vector<std::uint8_t> value{};
};

[[nodiscard]] std::vector<MessageField> message_to_fields(const BridgeMessage& msg);

[[nodiscard]] std::optional<BridgeMessage> message_from_fields(std::span<const MessageField> fields, const DecodeOptions& opt);

class ReplayProtectionStore final {
public:
    struct Options final {
        std::size_t max_entries{65536};
    };

    ReplayProtectionStore(std::filesystem::path data_dir, Options opt);

    [[nodiscard]] bool open();

    [[nodiscard]] bool contains(const crypto::Hash256& msg_hash) const;

    [[nodiscard]] bool accept(const crypto::Hash256& msg_hash);

    [[nodiscard]] std::size_t size() const;

private:
    std::filesystem::path data_dir_;
    Options opt_{};

    mutable Storage st_;

    [[nodiscard]] std::optional<std::uint64_t> load_u64(std::string_view key) const;
    [[nodiscard]] bool store_u64(Storage::Batch& b, std::string key, std::uint64_t v);

    [[nodiscard]] static std::string key_head();
    [[nodiscard]] static std::string key_tail();
    [[nodiscard]] static std::string key_seq(std::uint64_t seq);
    [[nodiscard]] static std::string key_hash(const crypto::Hash256& h);
};

}
