#include "rand/bridge/spec.hpp"

#include "rand/byte_cursor.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace randio::module113 {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{{'B', 'R', 'G', '1'}};

void encode_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void encode_u64_le(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

[[nodiscard]] std::vector<std::uint8_t> u64_le_bytes(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    encode_u64_le(out, v);
    return out;
}

[[nodiscard]] std::optional<std::uint64_t> parse_u64_le(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 8) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(bytes[static_cast<std::size_t>(i)]) << (8u * i));
    }
    return v;
}

[[nodiscard]] bool read_magic(module71::ByteCursor& c) {
    std::span<const std::uint8_t> m;
    if (c.read_bytes(4, m) != module71::ReadStatus::Ok) {
        return false;
    }
    return std::equal(m.begin(), m.end(), kMagic.begin());
}

} // namespace

bool BridgeMessage::operator==(const BridgeMessage& o) const {
    return chain_id_src == o.chain_id_src && chain_id_dst == o.chain_id_dst && nonce == o.nonce && asset_id == o.asset_id && amount == o.amount && sender == o.sender && recipient == o.recipient && payload == o.payload;
}

std::vector<std::uint8_t> encode_message(const BridgeMessage& msg, const DecodeOptions& opt) {
    std::vector<std::uint8_t> out;

    const std::size_t asset_n = std::min(msg.asset_id.size(), opt.max_asset_id_bytes);
    const std::size_t payload_n = std::min(msg.payload.size(), opt.max_payload_bytes);

    out.reserve(4 + 8 + 8 + 8 + 4 + asset_n + 8 + 32 + 32 + 4 + payload_n);

    out.insert(out.end(), kMagic.begin(), kMagic.end());
    encode_u64_le(out, msg.chain_id_src);
    encode_u64_le(out, msg.chain_id_dst);
    encode_u64_le(out, msg.nonce);

    encode_u32_le(out, static_cast<std::uint32_t>(asset_n));
    out.insert(out.end(), msg.asset_id.begin(), msg.asset_id.begin() + static_cast<std::ptrdiff_t>(asset_n));

    encode_u64_le(out, msg.amount);

    out.insert(out.end(), msg.sender.begin(), msg.sender.end());
    out.insert(out.end(), msg.recipient.begin(), msg.recipient.end());

    encode_u32_le(out, static_cast<std::uint32_t>(payload_n));
    out.insert(out.end(), msg.payload.begin(), msg.payload.begin() + static_cast<std::ptrdiff_t>(payload_n));

    return out;
}

std::optional<BridgeMessage> decode_message(const std::span<const std::uint8_t> bytes, const DecodeOptions& opt) {
    module71::ByteCursor c(bytes);

    if (!read_magic(c)) {
        return std::nullopt;
    }

    BridgeMessage msg;
    if (c.read_u64_le(msg.chain_id_src) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    if (c.read_u64_le(msg.chain_id_dst) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    if (c.read_u64_le(msg.nonce) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }

    std::uint32_t asset_len = 0;
    if (c.read_u32_le(asset_len) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    if (asset_len > opt.max_asset_id_bytes) {
        return std::nullopt;
    }
    std::span<const std::uint8_t> asset_bytes;
    if (c.read_bytes(asset_len, asset_bytes) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    msg.asset_id.assign(asset_bytes.begin(), asset_bytes.end());

    if (c.read_u64_le(msg.amount) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }

    std::span<const std::uint8_t> sender;
    if (c.read_bytes(msg.sender.size(), sender) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    std::copy(sender.begin(), sender.end(), msg.sender.begin());

    std::span<const std::uint8_t> recipient;
    if (c.read_bytes(msg.recipient.size(), recipient) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    std::copy(recipient.begin(), recipient.end(), msg.recipient.begin());

    std::uint32_t payload_len = 0;
    if (c.read_u32_le(payload_len) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    if (payload_len > opt.max_payload_bytes) {
        return std::nullopt;
    }
    std::span<const std::uint8_t> payload_bytes;
    if (c.read_bytes(payload_len, payload_bytes) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    msg.payload.assign(payload_bytes.begin(), payload_bytes.end());

    if (!c.eof()) {
        return std::nullopt;
    }

    return msg;
}

crypto::Hash256 message_hash(const BridgeMessage& msg, const DecodeOptions& opt) {
    const auto enc = encode_message(msg, opt);
    return crypto::sha256(std::span<const std::uint8_t>(enc.data(), enc.size()));
}

std::vector<MessageField> message_to_fields(const BridgeMessage& msg) {
    std::vector<MessageField> out;
    out.reserve(8);

    out.push_back(MessageField{FieldId::ChainIdSrc, u64_le_bytes(msg.chain_id_src)});
    out.push_back(MessageField{FieldId::ChainIdDst, u64_le_bytes(msg.chain_id_dst)});
    out.push_back(MessageField{FieldId::Nonce, u64_le_bytes(msg.nonce)});
    out.push_back(MessageField{FieldId::AssetId, msg.asset_id});
    out.push_back(MessageField{FieldId::Amount, u64_le_bytes(msg.amount)});
    out.push_back(MessageField{FieldId::Sender, std::vector<std::uint8_t>(msg.sender.begin(), msg.sender.end())});
    out.push_back(MessageField{FieldId::Recipient, std::vector<std::uint8_t>(msg.recipient.begin(), msg.recipient.end())});
    out.push_back(MessageField{FieldId::Payload, msg.payload});

    return out;
}

std::optional<BridgeMessage> message_from_fields(std::span<const MessageField> fields, const DecodeOptions& opt) {
    std::optional<std::vector<std::uint8_t>> chain_id_src;
    std::optional<std::vector<std::uint8_t>> chain_id_dst;
    std::optional<std::vector<std::uint8_t>> nonce;
    std::optional<std::vector<std::uint8_t>> asset_id;
    std::optional<std::vector<std::uint8_t>> amount;
    std::optional<std::vector<std::uint8_t>> sender;
    std::optional<std::vector<std::uint8_t>> recipient;
    std::optional<std::vector<std::uint8_t>> payload;

    auto take = [&](const FieldId id, const std::vector<std::uint8_t>& v) -> bool {
        switch (id) {
        case FieldId::ChainIdSrc:
            if (chain_id_src) {
                return false;
            }
            chain_id_src = v;
            return true;
        case FieldId::ChainIdDst:
            if (chain_id_dst) {
                return false;
            }
            chain_id_dst = v;
            return true;
        case FieldId::Nonce:
            if (nonce) {
                return false;
            }
            nonce = v;
            return true;
        case FieldId::AssetId:
            if (asset_id) {
                return false;
            }
            asset_id = v;
            return true;
        case FieldId::Amount:
            if (amount) {
                return false;
            }
            amount = v;
            return true;
        case FieldId::Sender:
            if (sender) {
                return false;
            }
            sender = v;
            return true;
        case FieldId::Recipient:
            if (recipient) {
                return false;
            }
            recipient = v;
            return true;
        case FieldId::Payload:
            if (payload) {
                return false;
            }
            payload = v;
            return true;
        default:
            return false;
        }
    };

    for (const auto& f : fields) {
        if (!take(f.id, f.value)) {
            return std::nullopt;
        }
    }

    if (!chain_id_src || !chain_id_dst || !nonce || !asset_id || !amount || !sender || !recipient || !payload) {
        return std::nullopt;
    }

    if (asset_id->size() > opt.max_asset_id_bytes || payload->size() > opt.max_payload_bytes) {
        return std::nullopt;
    }

    const auto src = parse_u64_le(std::span<const std::uint8_t>(chain_id_src->data(), chain_id_src->size()));
    const auto dst = parse_u64_le(std::span<const std::uint8_t>(chain_id_dst->data(), chain_id_dst->size()));
    const auto nn = parse_u64_le(std::span<const std::uint8_t>(nonce->data(), nonce->size()));
    const auto amt = parse_u64_le(std::span<const std::uint8_t>(amount->data(), amount->size()));
    if (!src || !dst || !nn || !amt) {
        return std::nullopt;
    }

    if (sender->size() != 32 || recipient->size() != 32) {
        return std::nullopt;
    }

    BridgeMessage out;
    out.chain_id_src = *src;
    out.chain_id_dst = *dst;
    out.nonce = *nn;
    out.asset_id = *asset_id;
    out.amount = *amt;
    std::copy(sender->begin(), sender->end(), out.sender.begin());
    std::copy(recipient->begin(), recipient->end(), out.recipient.begin());
    out.payload = *payload;
    return out;
}

ReplayProtectionStore::ReplayProtectionStore(std::filesystem::path data_dir, Options opt)
    : data_dir_(std::move(data_dir))
    , opt_(opt)
    , st_(data_dir_, Storage::Options{1}) {
}

bool ReplayProtectionStore::open() {
    if (!st_.open()) {
        return false;
    }

    const auto h = load_u64(key_head());
    const auto t = load_u64(key_tail());
    if (h.has_value() && t.has_value()) {
        return true;
    }

    auto b = st_.begin_batch();
    store_u64(b, key_head(), 0);
    store_u64(b, key_tail(), 0);
    return st_.commit(b);
}

std::optional<std::uint64_t> ReplayProtectionStore::load_u64(const std::string_view key) const {
    const auto bytes = st_.get(key);
    if (!bytes) {
        return std::nullopt;
    }
    if (bytes->size() != 8) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>((*bytes)[static_cast<std::size_t>(i)]) << (8u * i));
    }
    return v;
}

bool ReplayProtectionStore::store_u64(Storage::Batch& b, std::string key, const std::uint64_t v) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(8);
    encode_u64_le(bytes, v);
    st_.put(b, std::move(key), std::move(bytes));
    return true;
}

std::string ReplayProtectionStore::key_head() {
    return "bridge113:replay:head";
}

std::string ReplayProtectionStore::key_tail() {
    return "bridge113:replay:tail";
}

std::string ReplayProtectionStore::key_seq(const std::uint64_t seq) {
    return "bridge113:replay:seq:" + std::to_string(seq);
}

std::string ReplayProtectionStore::key_hash(const crypto::Hash256& h) {
    return "bridge113:replay:hash:" + crypto::to_hex(h);
}

bool ReplayProtectionStore::contains(const crypto::Hash256& msg_hash) const {
    const auto v = st_.get(key_hash(msg_hash));
    return v.has_value();
}

std::size_t ReplayProtectionStore::size() const {
    const auto h = load_u64(key_head());
    const auto t = load_u64(key_tail());
    if (!h || !t || *t < *h) {
        return 0;
    }
    return static_cast<std::size_t>(*t - *h);
}

bool ReplayProtectionStore::accept(const crypto::Hash256& msg_hash) {
    if (contains(msg_hash)) {
        return false;
    }

    const auto head0 = load_u64(key_head());
    const auto tail0 = load_u64(key_tail());
    if (!head0 || !tail0 || *tail0 < *head0) {
        return false;
    }

    std::uint64_t head = *head0;
    std::uint64_t tail = *tail0;

    auto b = st_.begin_batch();

    const auto seq = tail;
    tail += 1;

    std::vector<std::uint8_t> hash_bytes(msg_hash.begin(), msg_hash.end());
    st_.put(b, key_seq(seq), std::move(hash_bytes));
    store_u64(b, key_hash(msg_hash), seq);
    store_u64(b, key_tail(), tail);

    while (tail - head > opt_.max_entries) {
        const auto kseq = key_seq(head);
        const auto hv = st_.get(kseq);
        if (hv && hv->size() == 32) {
            crypto::Hash256 old{};
            std::copy(hv->begin(), hv->end(), old.begin());
            st_.erase(b, key_hash(old));
        }
        st_.erase(b, kseq);
        head += 1;
        store_u64(b, key_head(), head);
    }

    return st_.commit(b);
}

} // namespace randio::module113
