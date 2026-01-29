#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rand/block.hpp"
#include "rand/sha256.hpp"
#include "rand/state.hpp"
#include "rand/tx.hpp"

namespace randio::module80 {

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    Empty,
    TooShort,
    TooLong,
    BadMagic,
    BadVersion,
    BadKind,
    NonCanonical,
    Invalid,
};

struct DecodeOptions final {
    std::size_t max_total_bytes{2 * 1024 * 1024};
    std::size_t max_siblings{256};
    std::size_t max_id_bytes{256};
    std::size_t max_tx_bytes{1024 * 1024};
};

struct MerkleProof final {
    std::uint64_t leaf_index{0};
    std::uint64_t leaf_count{0};
    std::vector<crypto::Hash256> siblings;
};

[[nodiscard]] std::size_t merkle_depth(std::uint64_t leaf_count);

[[nodiscard]] crypto::Hash256 merkle_parent(const crypto::Hash256& left, const crypto::Hash256& right);

[[nodiscard]] std::optional<crypto::Hash256> compute_merkle_root(const crypto::Hash256& leaf_hash, const MerkleProof& p);
[[nodiscard]] bool verify_merkle_root(const crypto::Hash256& expected_root, const crypto::Hash256& leaf_hash, const MerkleProof& p);

struct TxInclusionProof final {
    BlockHeader header{};
    Transaction tx{};
    MerkleProof merkle;
};

struct AccountProof final {
    std::uint64_t height{0};
    crypto::Hash256 state_root{};
    std::string id;
    Account account{};
    MerkleProof merkle;
};

struct ReceiptInclusionProof final {
    BlockHeader header{};
    crypto::Hash256 txid{};
    bool applied{false};
    crypto::Hash256 receipt_root{};
    MerkleProof merkle;
};

[[nodiscard]] std::vector<std::uint8_t> encode_merkle_proof(const MerkleProof& p);
[[nodiscard]] DecodeStatus decode_merkle_proof(std::span<const std::uint8_t> bytes,
                                              MerkleProof& out,
                                              std::size_t& consumed,
                                              const DecodeOptions& opt);

[[nodiscard]] std::vector<std::uint8_t> encode_tx_inclusion_proof(const TxInclusionProof& p);
[[nodiscard]] DecodeStatus decode_tx_inclusion_proof(std::span<const std::uint8_t> bytes,
                                                    TxInclusionProof& out,
                                                    std::size_t& consumed,
                                                    const DecodeOptions& opt);

[[nodiscard]] std::vector<std::uint8_t> encode_account_proof(const AccountProof& p);
[[nodiscard]] DecodeStatus decode_account_proof(std::span<const std::uint8_t> bytes,
                                               AccountProof& out,
                                               std::size_t& consumed,
                                               const DecodeOptions& opt);

[[nodiscard]] std::vector<std::uint8_t> encode_receipt_inclusion_proof(const ReceiptInclusionProof& p);
[[nodiscard]] DecodeStatus decode_receipt_inclusion_proof(std::span<const std::uint8_t> bytes,
                                                         ReceiptInclusionProof& out,
                                                         std::size_t& consumed,
                                                         const DecodeOptions& opt);

[[nodiscard]] bool verify_tx_inclusion(const TxInclusionProof& p);
[[nodiscard]] bool verify_account_proof(const AccountProof& p);
[[nodiscard]] bool verify_receipt_inclusion(const ReceiptInclusionProof& p);

[[nodiscard]] crypto::Hash256 account_leaf_hash(std::string_view id, const Account& a);
[[nodiscard]] crypto::Hash256 receipt_leaf_hash(const crypto::Hash256& txid, bool applied);

}
