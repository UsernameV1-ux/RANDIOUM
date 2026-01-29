#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "rand/bridge/spec.hpp"
#include "rand/consensus/checkpoint.hpp"

namespace randio::module114 {

using ValidatorId = randio::ValidatorId;

struct AttestationSig final {
    ValidatorId validator_id;
    crypto::Hash256 signature{};
};

struct BridgeAttestation final {
    module113::BridgeMessage msg{};
    std::vector<AttestationSig> signatures;
};

struct DecodeOptions final {
    module113::DecodeOptions msg_opt{};
    std::size_t max_attested_message_bytes{16384};
    std::size_t max_signatures{256};
    std::size_t max_validator_id_bytes{1024};
};

struct VerifyOptions final {
    std::uint64_t quorum_num{2};
    std::uint64_t quorum_den{3};
};

[[nodiscard]] std::vector<std::uint8_t> encode_attested_message(const module113::BridgeMessage& msg, const module113::DecodeOptions& opt);

[[nodiscard]] std::optional<BridgeAttestation> normalize_bridge_attestation(const BridgeAttestation& a);

[[nodiscard]] std::vector<std::uint8_t> encode_bridge_attestation(const BridgeAttestation& a, const DecodeOptions& opt);

[[nodiscard]] std::optional<BridgeAttestation> decode_bridge_attestation(std::span<const std::uint8_t> bytes, const DecodeOptions& opt);

[[nodiscard]] consensus::VerifyStatus verify_bridge_attestation(const BridgeAttestation& a,
                                                               const ValidatorStore& keys,
                                                               const StakingLedger& staking,
                                                               const VerifyOptions& opt);

[[nodiscard]] crypto::Hash256 attested_message_hash(const module113::BridgeMessage& msg, const module113::DecodeOptions& opt);

}
