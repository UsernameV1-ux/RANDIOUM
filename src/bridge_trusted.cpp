#include "rand/bridge/trusted.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

namespace randio::module114 {
namespace {

constexpr std::uint32_t kBridgeAttestationMagic = 0x31544142u;
constexpr std::uint32_t kBridgeAttestationFormatV1 = 1u;

void append_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
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

} // namespace

std::vector<std::uint8_t> encode_attested_message(const module113::BridgeMessage& msg, const module113::DecodeOptions& opt) {
    return module113::encode_message(msg, opt);
}

crypto::Hash256 attested_message_hash(const module113::BridgeMessage& msg, const module113::DecodeOptions& opt) {
    return module113::message_hash(msg, opt);
}

std::optional<BridgeAttestation> normalize_bridge_attestation(const BridgeAttestation& a) {
    BridgeAttestation out = a;
    std::sort(out.signatures.begin(), out.signatures.end(), [](const AttestationSig& x, const AttestationSig& y) {
        return x.validator_id < y.validator_id;
    });

    for (std::size_t i = 1; i < out.signatures.size(); ++i) {
        if (out.signatures[i - 1].validator_id == out.signatures[i].validator_id) {
            return std::nullopt;
        }
    }

    return out;
}

std::vector<std::uint8_t> encode_bridge_attestation(const BridgeAttestation& a, const DecodeOptions& opt) {
    const auto msg_bytes = encode_attested_message(a.msg, opt.msg_opt);

    BridgeAttestation canon = a;
    std::sort(canon.signatures.begin(), canon.signatures.end(), [](const AttestationSig& x, const AttestationSig& y) {
        return x.validator_id < y.validator_id;
    });

    std::vector<std::uint8_t> out;
    out.reserve(4 + 4 + 4 + msg_bytes.size() + 4 + canon.signatures.size() * (4 + 64));

    append_u32_le(out, kBridgeAttestationMagic);
    append_u32_le(out, kBridgeAttestationFormatV1);

    append_u32_le(out, static_cast<std::uint32_t>(msg_bytes.size()));
    out.insert(out.end(), msg_bytes.begin(), msg_bytes.end());

    append_u32_le(out, static_cast<std::uint32_t>(canon.signatures.size()));

    for (const auto& s : canon.signatures) {
        append_u32_le(out, static_cast<std::uint32_t>(s.validator_id.size()));
        out.insert(out.end(), s.validator_id.begin(), s.validator_id.end());
        out.insert(out.end(), s.signature.begin(), s.signature.end());
    }

    return out;
}

std::optional<BridgeAttestation> decode_bridge_attestation(std::span<const std::uint8_t> bytes, const DecodeOptions& opt) {
    std::size_t off = 0;

    const auto magic = read_u32_le(bytes, off);
    const auto fmt = read_u32_le(bytes, off);
    if (!magic || !fmt) {
        return std::nullopt;
    }
    if (*magic != kBridgeAttestationMagic || *fmt != kBridgeAttestationFormatV1) {
        return std::nullopt;
    }

    const auto msg_len = read_u32_le(bytes, off);
    if (!msg_len) {
        return std::nullopt;
    }
    if (*msg_len > opt.max_attested_message_bytes) {
        return std::nullopt;
    }
    if (off + *msg_len > bytes.size()) {
        return std::nullopt;
    }

    const auto msg_bytes = std::span<const std::uint8_t>(bytes.data() + off, static_cast<std::size_t>(*msg_len));
    off += *msg_len;

    const auto msg = module113::decode_message(msg_bytes, opt.msg_opt);
    if (!msg) {
        return std::nullopt;
    }

    const auto cnt = read_u32_le(bytes, off);
    if (!cnt) {
        return std::nullopt;
    }
    if (*cnt > opt.max_signatures) {
        return std::nullopt;
    }

    BridgeAttestation out;
    out.msg = *msg;
    out.signatures.clear();
    out.signatures.reserve(*cnt);

    for (std::uint32_t i = 0; i < *cnt; ++i) {
        const auto len = read_u32_le(bytes, off);
        if (!len) {
            return std::nullopt;
        }
        if (*len > opt.max_validator_id_bytes) {
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

        out.signatures.push_back(AttestationSig{std::move(id), sig});
    }

    if (off != bytes.size()) {
        return std::nullopt;
    }

    return out;
}

consensus::VerifyStatus verify_bridge_attestation(const BridgeAttestation& a,
                                                 const ValidatorStore& keys,
                                                 const StakingLedger& staking,
                                                 const VerifyOptions& opt) {
    if (opt.quorum_den == 0 || opt.quorum_num == 0 || opt.quorum_num > opt.quorum_den) {
        return consensus::VerifyStatus::InvalidHeader;
    }

    module113::DecodeOptions msg_opt;
    const auto msg_bytes = encode_attested_message(a.msg, msg_opt);

    std::unordered_set<ValidatorId> seen;
    std::uint64_t signed_stake = 0;

    for (const auto& s : a.signatures) {
        if (s.validator_id.empty()) {
            return consensus::VerifyStatus::UnknownValidator;
        }
        if (seen.find(s.validator_id) != seen.end()) {
            return consensus::VerifyStatus::DuplicateSigner;
        }
        seen.insert(s.validator_id);

        if (staking.is_slashed(s.validator_id)) {
            return consensus::VerifyStatus::UnknownValidator;
        }
        const auto stake = staking.bonded_of(s.validator_id);
        if (stake == 0) {
            return consensus::VerifyStatus::UnknownValidator;
        }

        const auto pk = keys.pubkey(s.validator_id);
        if (!pk) {
            return consensus::VerifyStatus::MissingPubkey;
        }

        if (!verify_signature(*pk, std::span<const std::uint8_t>(msg_bytes.data(), msg_bytes.size()), s.signature)) {
            return consensus::VerifyStatus::InvalidSignature;
        }

        const auto next = signed_stake + stake;
        if (next < signed_stake) {
            return consensus::VerifyStatus::QuorumNotMet;
        }
        signed_stake = next;
    }

    const auto total = staking.total_bonded();
    if (total == 0) {
        return consensus::VerifyStatus::QuorumNotMet;
    }

    const unsigned __int128 lhs = static_cast<unsigned __int128>(signed_stake) * static_cast<unsigned __int128>(opt.quorum_den);
    const unsigned __int128 rhs = static_cast<unsigned __int128>(total) * static_cast<unsigned __int128>(opt.quorum_num);
    if (lhs < rhs) {
        return consensus::VerifyStatus::QuorumNotMet;
    }

    return consensus::VerifyStatus::Ok;
}

}
