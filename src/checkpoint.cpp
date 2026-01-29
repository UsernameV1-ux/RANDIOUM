#include "rand/consensus/checkpoint.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

namespace randio::consensus {
namespace {

constexpr std::uint32_t kSignedCheckpointMagic = 0x54504B43u;
constexpr std::uint32_t kSignedCheckpointFormatV1 = 1u;

void append_u16_le(std::vector<std::uint8_t>& out, const std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

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

[[nodiscard]] std::optional<std::uint32_t> read_u32_le(std::span<const std::uint8_t> bytes, std::size_t& off) {
    if (off + 4 > bytes.size()) {
        return std::nullopt;
    }
    const auto* p = bytes.data() + off;
    off += 4;
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) | (static_cast<std::uint32_t>(p[2]) << 16u) |
           (static_cast<std::uint32_t>(p[3]) << 24u);
}

[[nodiscard]] std::optional<std::uint64_t> read_u64_le(std::span<const std::uint8_t> bytes, std::size_t& off) {
    if (off + 8 > bytes.size()) {
        return std::nullopt;
    }
    const auto* p = bytes.data() + off;
    off += 8;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
    }
    return v;
}

[[nodiscard]] std::optional<std::uint16_t> read_u16_le(std::span<const std::uint8_t> bytes, std::size_t& off) {
    if (off + 2 > bytes.size()) {
        return std::nullopt;
    }
    const auto* p = bytes.data() + off;
    off += 2;
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8u);
}

}

std::vector<std::uint8_t> encode_checkpoint_header(const CheckpointHeader& h) {
    std::vector<std::uint8_t> out;
    out.reserve(8 + 32 + 32 + 2);
    append_u64_le(out, h.height);
    out.insert(out.end(), h.block_hash.begin(), h.block_hash.end());
    out.insert(out.end(), h.state_root.begin(), h.state_root.end());
    append_u16_le(out, h.protocol_version);
    return out;
}

std::optional<SignedCheckpoint> normalize_signed_checkpoint(const SignedCheckpoint& cp) {
    SignedCheckpoint out = cp;
    std::sort(out.signatures.begin(), out.signatures.end(), [](const CheckpointSig& a, const CheckpointSig& b) {
        return a.validator_id < b.validator_id;
    });

    for (std::size_t i = 1; i < out.signatures.size(); ++i) {
        if (out.signatures[i - 1].validator_id == out.signatures[i].validator_id) {
            return std::nullopt;
        }
    }

    return out;
}

VerifyStatus verify_signed_checkpoint(const SignedCheckpoint& cp, const ValidatorStore& keys, const StakingLedger& staking) {
    const auto msg = encode_checkpoint_header(cp.header);

    std::unordered_set<ValidatorId> seen;
    std::uint64_t signed_stake = 0;

    for (const auto& s : cp.signatures) {
        if (s.validator_id.empty()) {
            return VerifyStatus::UnknownValidator;
        }
        if (seen.find(s.validator_id) != seen.end()) {
            return VerifyStatus::DuplicateSigner;
        }
        seen.insert(s.validator_id);

        if (staking.is_slashed(s.validator_id)) {
            return VerifyStatus::UnknownValidator;
        }
        const auto stake = staking.bonded_of(s.validator_id);
        if (stake == 0) {
            return VerifyStatus::UnknownValidator;
        }

        const auto pk = keys.pubkey(s.validator_id);
        if (!pk) {
            return VerifyStatus::MissingPubkey;
        }

        if (!verify_signature(*pk, std::span<const std::uint8_t>(msg.data(), msg.size()), s.signature)) {
            return VerifyStatus::InvalidSignature;
        }

        const auto next = signed_stake + stake;
        if (next < signed_stake) {
            return VerifyStatus::QuorumNotMet;
        }
        signed_stake = next;
    }

    const auto total = staking.total_bonded();
    if (total == 0) {
        return VerifyStatus::QuorumNotMet;
    }

    const unsigned __int128 lhs = static_cast<unsigned __int128>(signed_stake) * static_cast<unsigned __int128>(3);
    const unsigned __int128 rhs = static_cast<unsigned __int128>(total) * static_cast<unsigned __int128>(2);
    if (lhs < rhs) {
        return VerifyStatus::QuorumNotMet;
    }

    return VerifyStatus::Ok;
}

bool is_better_checkpoint(const SignedCheckpoint& a, const SignedCheckpoint& b) {
    if (a.header.height != b.header.height) {
        return a.header.height > b.header.height;
    }
    if (a.header.block_hash != b.header.block_hash) {
        return a.header.block_hash < b.header.block_hash;
    }
    if (a.header.state_root != b.header.state_root) {
        return a.header.state_root < b.header.state_root;
    }
    return a.header.protocol_version > b.header.protocol_version;
}

std::vector<std::uint8_t> encode_signed_checkpoint(const SignedCheckpoint& cp) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + 4 + 8 + 32 + 32 + 2 + 4 + cp.signatures.size() * (4 + 32 + 64));

    append_u32_le(out, kSignedCheckpointMagic);
    append_u32_le(out, kSignedCheckpointFormatV1);

    const auto hdr = encode_checkpoint_header(cp.header);
    out.insert(out.end(), hdr.begin(), hdr.end());

    append_u32_le(out, static_cast<std::uint32_t>(cp.signatures.size()));

    for (const auto& s : cp.signatures) {
        append_u32_le(out, static_cast<std::uint32_t>(s.validator_id.size()));
        out.insert(out.end(), s.validator_id.begin(), s.validator_id.end());
        out.insert(out.end(), s.signature.begin(), s.signature.end());
    }

    return out;
}

std::optional<SignedCheckpoint> decode_signed_checkpoint(const std::span<const std::uint8_t> bytes) {
    std::size_t off = 0;

    const auto magic = read_u32_le(bytes, off);
    const auto fmt = read_u32_le(bytes, off);
    if (!magic || !fmt) {
        return std::nullopt;
    }
    if (*magic != kSignedCheckpointMagic || *fmt != kSignedCheckpointFormatV1) {
        return std::nullopt;
    }

    auto height = read_u64_le(bytes, off);
    if (!height) {
        return std::nullopt;
    }

    if (off + 32 + 32 > bytes.size()) {
        return std::nullopt;
    }
    crypto::Hash256 bh{};
    crypto::Hash256 sr{};
    std::copy(bytes.data() + off, bytes.data() + off + 32, bh.begin());
    off += 32;
    std::copy(bytes.data() + off, bytes.data() + off + 32, sr.begin());
    off += 32;

    const auto pv = read_u16_le(bytes, off);
    if (!pv) {
        return std::nullopt;
    }

    const auto cnt = read_u32_le(bytes, off);
    if (!cnt) {
        return std::nullopt;
    }

    SignedCheckpoint cp;
    cp.header.height = *height;
    cp.header.block_hash = bh;
    cp.header.state_root = sr;
    cp.header.protocol_version = *pv;

    cp.signatures.clear();
    cp.signatures.reserve(*cnt);

    for (std::uint32_t i = 0; i < *cnt; ++i) {
        const auto len = read_u32_le(bytes, off);
        if (!len) {
            return std::nullopt;
        }
        if (*len > 1024) {
            return std::nullopt;
        }
        if (off + *len > bytes.size()) {
            return std::nullopt;
        }
        std::string id(reinterpret_cast<const char*>(bytes.data() + off), reinterpret_cast<const char*>(bytes.data() + off + *len));
        off += *len;

        if (off + 32 > bytes.size()) {
            return std::nullopt;
        }
        crypto::Hash256 sig{};
        std::copy(bytes.data() + off, bytes.data() + off + 32, sig.begin());
        off += 32;

        cp.signatures.push_back(CheckpointSig{std::move(id), sig});
    }

    if (off != bytes.size()) {
        return std::nullopt;
    }

    return cp;
}

}
