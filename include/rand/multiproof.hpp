#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "rand/sha256.hpp"

namespace randio::module81 {

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    Empty,
    TooShort,
    TooLong,
    BadMagic,
    BadVersion,
    NonCanonical,
    Invalid,
};

struct DecodeOptions final {
    std::size_t max_total_bytes{2 * 1024 * 1024};
    std::size_t max_leaves{4096};
    std::size_t max_side_nodes{16384};
};

struct NodePos final {
    std::uint64_t level{0};
    std::uint64_t index{0};
};

struct SideNode final {
    NodePos pos{};
    crypto::Hash256 hash{};
};

struct LeafItem final {
    std::uint64_t leaf_index{0};
    crypto::Hash256 leaf_hash{};
};

struct MerkleMultiProof final {
    std::uint64_t leaf_count{0};
    std::vector<LeafItem> leaves;
    std::vector<SideNode> side_nodes;
};

[[nodiscard]] std::vector<std::uint8_t> encode_multiproof(const MerkleMultiProof& p);
[[nodiscard]] DecodeStatus decode_multiproof(std::span<const std::uint8_t> bytes,
                                            MerkleMultiProof& out,
                                            std::size_t& consumed,
                                            const DecodeOptions& opt);

[[nodiscard]] std::optional<crypto::Hash256> verify_and_root(const MerkleMultiProof& p);

[[nodiscard]] std::optional<MerkleMultiProof> build_from_leaves(std::span<const crypto::Hash256> full_leaves,
                                                               std::span<const std::uint64_t> target_leaf_indices);

}
