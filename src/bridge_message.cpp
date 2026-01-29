#include "rand/bridge/message.hpp"

#include "rand/byte_cursor.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace randio::module115 {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic{{'B', 'R', 'G', '2'}};
constexpr std::uint32_t kFormatV1 = 1u;

void append_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

[[nodiscard]] bool read_magic(module71::ByteCursor& c) {
    std::span<const std::uint8_t> m;
    if (c.read_bytes(4, m) != module71::ReadStatus::Ok) {
        return false;
    }
    return std::equal(m.begin(), m.end(), kMagic.begin());
}

[[nodiscard]] crypto::Hash256 compute_msg_id_(const std::vector<std::uint8_t>& enc) {
    std::vector<std::uint8_t> buf;
    static constexpr std::string_view kDomain = "randium:bridge115:msgid:v2";
    buf.reserve(kDomain.size() + enc.size());
    buf.insert(buf.end(), kDomain.begin(), kDomain.end());
    buf.insert(buf.end(), enc.begin(), enc.end());
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

} // namespace

bool BridgePayload::operator==(const BridgePayload& o) const {
    return amount == o.amount && token_id == o.token_id && recipient == o.recipient && memo == o.memo;
}

bool BridgeMessageV2::operator==(const BridgeMessageV2& o) const {
    return chain_id_src == o.chain_id_src && chain_id_dst == o.chain_id_dst && nonce == o.nonce && expiry_height == o.expiry_height && payload == o.payload;
}

std::optional<std::vector<std::uint8_t>> encode_message_v2(const BridgeMessageV2& msg, const DecodeOptions& opt) {
    if (msg.payload.memo.size() > opt.max_memo_bytes) {
        return std::nullopt;
    }

    const std::size_t total = 4 + 4 + 8 + 8 + 8 + 8 + 8 + 32 + 32 + 4 + msg.payload.memo.size();
    if (total > opt.max_total_bytes) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> out;
    out.reserve(total);

    out.insert(out.end(), kMagic.begin(), kMagic.end());
    append_u32_le(out, kFormatV1);

    append_u64_le(out, msg.chain_id_src);
    append_u64_le(out, msg.chain_id_dst);
    append_u64_le(out, msg.nonce);
    append_u64_le(out, msg.expiry_height);

    append_u64_le(out, msg.payload.amount);
    out.insert(out.end(), msg.payload.token_id.begin(), msg.payload.token_id.end());
    out.insert(out.end(), msg.payload.recipient.begin(), msg.payload.recipient.end());

    append_u32_le(out, static_cast<std::uint32_t>(msg.payload.memo.size()));
    out.insert(out.end(), msg.payload.memo.begin(), msg.payload.memo.end());

    return out;
}

std::optional<BridgeMessageV2> decode_message_v2(const std::span<const std::uint8_t> bytes, const DecodeOptions& opt) {
    if (bytes.empty() || bytes.size() > opt.max_total_bytes) {
        return std::nullopt;
    }

    module71::ByteCursor c(bytes);

    if (!read_magic(c)) {
        return std::nullopt;
    }

    std::uint32_t ver = 0;
    if (c.read_u32_le(ver) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    if (ver != kFormatV1) {
        return std::nullopt;
    }

    BridgeMessageV2 msg;
    if (c.read_u64_le(msg.chain_id_src) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    if (c.read_u64_le(msg.chain_id_dst) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    if (c.read_u64_le(msg.nonce) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    if (c.read_u64_le(msg.expiry_height) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }

    if (c.read_u64_le(msg.payload.amount) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }

    {
        std::span<const std::uint8_t> tid;
        if (c.read_bytes(msg.payload.token_id.size(), tid) != module71::ReadStatus::Ok) {
            return std::nullopt;
        }
        std::copy(tid.begin(), tid.end(), msg.payload.token_id.begin());
    }

    {
        std::span<const std::uint8_t> rec;
        if (c.read_bytes(msg.payload.recipient.size(), rec) != module71::ReadStatus::Ok) {
            return std::nullopt;
        }
        std::copy(rec.begin(), rec.end(), msg.payload.recipient.begin());
    }

    std::uint32_t memo_len = 0;
    if (c.read_u32_le(memo_len) != module71::ReadStatus::Ok) {
        return std::nullopt;
    }
    if (memo_len > opt.max_memo_bytes) {
        return std::nullopt;
    }

    {
        std::span<const std::uint8_t> memo;
        if (c.read_bytes(memo_len, memo) != module71::ReadStatus::Ok) {
            return std::nullopt;
        }
        msg.payload.memo.assign(memo.begin(), memo.end());
    }

    if (!c.eof()) {
        return std::nullopt;
    }

    return msg;
}

MsgId message_id_v2(const BridgeMessageV2& msg, const DecodeOptions& opt) {
    const auto enc = encode_message_v2(msg, opt);
    if (!enc) {
        return crypto::Hash256{};
    }
    return compute_msg_id_(*enc);
}

}
