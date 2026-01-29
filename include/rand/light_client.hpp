#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "rand/light_sync.hpp"
#include "rand/proof.hpp"

namespace randio::module83 {

enum class VerifyStatus : std::uint8_t {
    Ok = 0,
    DecodeError,
    MissingCanonicalHeader,
    MissingTrustedRoot,
    RootMismatch,
    ProofInvalid,
};

struct VerifierOptions final {
    module82::SyncOptions sync{};
    module80::DecodeOptions proof_decode{};
};

class LightClientVerifier final {
public:
    explicit LightClientVerifier(VerifierOptions opt);

    void set_checkpoints(std::vector<module82::Checkpoint> cps);

    [[nodiscard]] module82::AddStatus add_header(const BlockHeader& h);

    [[nodiscard]] std::optional<crypto::Hash256> tip_hash() const;
    [[nodiscard]] std::optional<std::uint64_t> tip_height() const;

    void set_trusted_state_root(std::uint64_t height, const crypto::Hash256& state_root);
    void set_trusted_receipt_root(std::uint64_t height, const crypto::Hash256& receipt_root);

    [[nodiscard]] VerifyStatus verify_tx_inclusion_proof(const module80::TxInclusionProof& p) const;
    [[nodiscard]] VerifyStatus verify_account_proof(const module80::AccountProof& p) const;
    [[nodiscard]] VerifyStatus verify_receipt_inclusion_proof(const module80::ReceiptInclusionProof& p) const;

    [[nodiscard]] VerifyStatus verify_tx_inclusion_proof_bytes(std::span<const std::uint8_t> bytes) const;
    [[nodiscard]] VerifyStatus verify_account_proof_bytes(std::span<const std::uint8_t> bytes) const;
    [[nodiscard]] VerifyStatus verify_receipt_inclusion_proof_bytes(std::span<const std::uint8_t> bytes) const;

private:
    VerifierOptions opt_{};
    module82::LightHeaderSync sync_;

    std::map<std::uint64_t, crypto::Hash256> trusted_state_roots_;
    std::map<std::uint64_t, crypto::Hash256> trusted_receipt_roots_;

    [[nodiscard]] bool is_canonical_header_(const BlockHeader& h) const;
    [[nodiscard]] std::optional<crypto::Hash256> trusted_state_root_(std::uint64_t height) const;
    [[nodiscard]] std::optional<crypto::Hash256> trusted_receipt_root_(std::uint64_t height) const;
};

}
