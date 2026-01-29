#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "rand/sha256.hpp"
#include "rand/staking.hpp"
#include "rand/validator.hpp"

namespace randio::consensus {

struct CheckpointHeader final {
    std::uint64_t height{0};
    crypto::Hash256 block_hash{};
    crypto::Hash256 state_root{};
    std::uint16_t protocol_version{0};
};

struct CheckpointSig final {
    ValidatorId validator_id;
    crypto::Hash256 signature{};
};

struct SignedCheckpoint final {
    CheckpointHeader header{};
    std::vector<CheckpointSig> signatures;
};

enum class VerifyStatus : std::uint8_t {
    Ok = 0,
    InvalidHeader,
    DuplicateSigner,
    UnknownValidator,
    MissingPubkey,
    InvalidSignature,
    QuorumNotMet,
};

[[nodiscard]] std::vector<std::uint8_t> encode_checkpoint_header(const CheckpointHeader& h);

[[nodiscard]] std::optional<SignedCheckpoint> normalize_signed_checkpoint(const SignedCheckpoint& cp);

[[nodiscard]] VerifyStatus verify_signed_checkpoint(const SignedCheckpoint& cp, const ValidatorStore& keys, const StakingLedger& staking);

[[nodiscard]] bool is_better_checkpoint(const SignedCheckpoint& a, const SignedCheckpoint& b);

[[nodiscard]] std::vector<std::uint8_t> encode_signed_checkpoint(const SignedCheckpoint& cp);
[[nodiscard]] std::optional<SignedCheckpoint> decode_signed_checkpoint(std::span<const std::uint8_t> bytes);

}
