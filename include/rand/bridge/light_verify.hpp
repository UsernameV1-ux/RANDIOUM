#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "rand/block.hpp"
#include "rand/chain_db.hpp"
#include "rand/bridge/message.hpp"
#include "rand/consensus/checkpoint.hpp"
#include "rand/light_client.hpp"
#include "rand/proof.hpp"
#include "rand/state.hpp"

namespace randio::module115 {

enum class VerifyCode : std::uint8_t {
    Ok = 0,

    DecodeMessageError,
    NonCanonicalMessage,

    MissingCheckpoint,
    HeaderRejected,

    MissingTxProof,
    TxProofDecodeError,
    TxPayloadMismatch,
    TxProofInvalid,

    ReceiptProofDecodeError,
    ReceiptProofInvalid,
};

struct VerifyInput final {
    std::span<const std::uint8_t> message_bytes{};

    std::optional<std::span<const std::uint8_t>> tx_inclusion_proof_bytes{};
    std::optional<std::span<const std::uint8_t>> receipt_inclusion_proof_bytes{};

    std::span<const BlockHeader> headers{};
    std::span<const module82::Checkpoint> checkpoints{};

    std::optional<crypto::Hash256> trusted_receipt_root{};
};

struct VerifyOutput final {
    VerifyCode code{VerifyCode::DecodeMessageError};
    MsgId msg_id{};
    std::uint64_t proof_height{0};
};

struct VerifyOptions final {
    DecodeOptions msg_decode{};
    module83::VerifierOptions lc{};
};

[[nodiscard]] VerifyOutput verify_message_light(const VerifyInput& in, const VerifyOptions& opt);

}

namespace randio::bridge::module115 {

struct VerifyOptions final {
    std::uint32_t min_protocol_version{0};
    std::uint32_t max_protocol_version{0};
    std::uint64_t max_message_bytes{0};
    std::uint64_t max_proof_bytes{0};
};

enum class VerifyError : std::uint32_t {
    Ok = 0,
    BadFormat,
    BadVersion,
    BadCheckpoint,
    BadProof,
    PayloadMismatch,
    Replay,
    Overflow,
};

struct VerifyResult final {
    VerifyError err{VerifyError::BadFormat};
    crypto::Hash256 msg_id{};
};

[[nodiscard]] VerifyResult verify_message(const GlobalState& st,
                                         const ChainDB& db,
                                         const VerifyOptions& opt,
                                         const randio::module115::BridgeMessageV2& msg,
                                         std::span<const std::uint8_t> proof_bytes);

}
