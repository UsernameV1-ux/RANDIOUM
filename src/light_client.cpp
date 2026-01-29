#include "rand/light_client.hpp"

#include "rand/block.hpp"

namespace randio::module83 {

LightClientVerifier::LightClientVerifier(VerifierOptions opt) : opt_(opt), sync_(opt.sync) {}

void LightClientVerifier::set_checkpoints(std::vector<module82::Checkpoint> cps) {
    sync_.set_checkpoints(std::move(cps));
}

module82::AddStatus LightClientVerifier::add_header(const BlockHeader& h) {
    return sync_.add_header(h);
}

std::optional<crypto::Hash256> LightClientVerifier::tip_hash() const {
    return sync_.tip_hash();
}

std::optional<std::uint64_t> LightClientVerifier::tip_height() const {
    return sync_.tip_height();
}

void LightClientVerifier::set_trusted_state_root(const std::uint64_t height, const crypto::Hash256& state_root) {
    trusted_state_roots_[height] = state_root;
}

void LightClientVerifier::set_trusted_receipt_root(const std::uint64_t height, const crypto::Hash256& receipt_root) {
    trusted_receipt_roots_[height] = receipt_root;
}

bool LightClientVerifier::is_canonical_header_(const BlockHeader& h) const {
    const auto tiph = sync_.tip_height();
    if (!tiph.has_value()) {
        return false;
    }
    if (h.height > *tiph) {
        return false;
    }

    const auto ha = sync_.hash_at_height(h.height);
    if (!ha.has_value()) {
        return false;
    }

    return (*ha == block_hash(h));
}

std::optional<crypto::Hash256> LightClientVerifier::trusted_state_root_(const std::uint64_t height) const {
    const auto it = trusted_state_roots_.find(height);
    if (it == trusted_state_roots_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<crypto::Hash256> LightClientVerifier::trusted_receipt_root_(const std::uint64_t height) const {
    const auto it = trusted_receipt_roots_.find(height);
    if (it == trusted_receipt_roots_.end()) {
        return std::nullopt;
    }
    return it->second;
}

VerifyStatus LightClientVerifier::verify_tx_inclusion_proof(const module80::TxInclusionProof& p) const {
    if (!is_canonical_header_(p.header)) {
        return VerifyStatus::MissingCanonicalHeader;
    }

    if (!module80::verify_tx_inclusion(p)) {
        return VerifyStatus::ProofInvalid;
    }

    return VerifyStatus::Ok;
}

VerifyStatus LightClientVerifier::verify_account_proof(const module80::AccountProof& p) const {
    const auto sr = trusted_state_root_(p.height);
    if (!sr.has_value()) {
        return VerifyStatus::MissingTrustedRoot;
    }
    if (*sr != p.state_root) {
        return VerifyStatus::RootMismatch;
    }

    if (!module80::verify_account_proof(p)) {
        return VerifyStatus::ProofInvalid;
    }

    return VerifyStatus::Ok;
}

VerifyStatus LightClientVerifier::verify_receipt_inclusion_proof(const module80::ReceiptInclusionProof& p) const {
    if (!is_canonical_header_(p.header)) {
        return VerifyStatus::MissingCanonicalHeader;
    }

    const auto rr = trusted_receipt_root_(p.header.height);
    if (!rr.has_value()) {
        return VerifyStatus::MissingTrustedRoot;
    }
    if (*rr != p.receipt_root) {
        return VerifyStatus::RootMismatch;
    }

    if (!module80::verify_receipt_inclusion(p)) {
        return VerifyStatus::ProofInvalid;
    }

    return VerifyStatus::Ok;
}

VerifyStatus LightClientVerifier::verify_tx_inclusion_proof_bytes(std::span<const std::uint8_t> bytes) const {
    module80::TxInclusionProof p;
    std::size_t consumed = 0;
    const auto st = module80::decode_tx_inclusion_proof(bytes, p, consumed, opt_.proof_decode);
    if (st != module80::DecodeStatus::Ok || consumed != bytes.size()) {
        return VerifyStatus::DecodeError;
    }
    return verify_tx_inclusion_proof(p);
}

VerifyStatus LightClientVerifier::verify_account_proof_bytes(std::span<const std::uint8_t> bytes) const {
    module80::AccountProof p;
    std::size_t consumed = 0;
    const auto st = module80::decode_account_proof(bytes, p, consumed, opt_.proof_decode);
    if (st != module80::DecodeStatus::Ok || consumed != bytes.size()) {
        return VerifyStatus::DecodeError;
    }
    return verify_account_proof(p);
}

VerifyStatus LightClientVerifier::verify_receipt_inclusion_proof_bytes(std::span<const std::uint8_t> bytes) const {
    module80::ReceiptInclusionProof p;
    std::size_t consumed = 0;
    const auto st = module80::decode_receipt_inclusion_proof(bytes, p, consumed, opt_.proof_decode);
    if (st != module80::DecodeStatus::Ok || consumed != bytes.size()) {
        return VerifyStatus::DecodeError;
    }
    return verify_receipt_inclusion_proof(p);
}

}
