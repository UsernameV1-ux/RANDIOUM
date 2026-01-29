#include "rand/multiproof.hpp"

#include "rand/sha256.hpp"
#include "rand/varint.hpp"

#include <algorithm>
#include <array>
#include <unordered_map>

namespace randio::module81 {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {static_cast<std::uint8_t>('R'), static_cast<std::uint8_t>('M'),
                                               static_cast<std::uint8_t>('P'), static_cast<std::uint8_t>('F')};
constexpr std::uint8_t kVersion = 1;

struct Key final {
    std::uint64_t level{0};
    std::uint64_t index{0};
};

struct KeyHash final {
    std::size_t operator()(const Key& k) const {
        const auto a = std::hash<std::uint64_t>{}(k.level);
        const auto b = std::hash<std::uint64_t>{}(k.index);
        return a ^ (b + 0x9e3779b97f4a7c15ull + (a << 6u) + (a >> 2u));
    }
};

struct KeyEq final {
    bool operator()(const Key& a, const Key& b) const {
        return a.level == b.level && a.index == b.index;
    }
};

[[nodiscard]] std::uint64_t node_count_at_level(const std::uint64_t leaf_count, const std::uint64_t level) {
    std::uint64_t n = leaf_count;
    for (std::uint64_t i = 0; i < level; ++i) {
        if (n <= 1) {
            return 1;
        }
        n = (n + 1) / 2;
    }
    return (n == 0) ? 1 : n;
}

[[nodiscard]] std::uint64_t tree_depth(const std::uint64_t leaf_count) {
    std::uint64_t n = leaf_count;
    std::uint64_t d = 0;
    while (n > 1) {
        n = (n + 1) / 2;
        d += 1;
    }
    return d;
}

[[nodiscard]] crypto::Hash256 merkle_parent(const crypto::Hash256& left, const crypto::Hash256& right) {
    std::array<std::uint8_t, 64> buf{};
    std::copy(left.begin(), left.end(), buf.begin());
    std::copy(right.begin(), right.end(), buf.begin() + 32);
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

[[nodiscard]] bool read_u8(std::span<const std::uint8_t> bytes, std::size_t& off, std::uint8_t& out) {
    if (off + 1 > bytes.size()) {
        return false;
    }
    out = bytes[off];
    off += 1;
    return true;
}

[[nodiscard]] bool read_hash256(std::span<const std::uint8_t> bytes, std::size_t& off, crypto::Hash256& out) {
    if (off + 32 > bytes.size()) {
        return false;
    }
    std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(off),
              bytes.begin() + static_cast<std::ptrdiff_t>(off + 32),
              out.begin());
    off += 32;
    return true;
}

[[nodiscard]] DecodeStatus read_var_u64(std::span<const std::uint8_t> bytes,
                                       std::size_t& off,
                                       std::uint64_t& out,
                                       const module70::DecodeOptions& vopt) {
    if (off >= bytes.size()) {
        return DecodeStatus::TooShort;
    }
    std::size_t consumed = 0;
    const auto st = module70::decode_u64(bytes.subspan(off), out, consumed, vopt);
    if (st == module70::DecodeStatus::Empty) {
        return DecodeStatus::Empty;
    }
    if (st == module70::DecodeStatus::Unterminated || st == module70::DecodeStatus::TooLong) {
        return DecodeStatus::TooShort;
    }
    if (st == module70::DecodeStatus::Overflow || st == module70::DecodeStatus::NonCanonical) {
        return DecodeStatus::NonCanonical;
    }
    if (st != module70::DecodeStatus::Ok) {
        return DecodeStatus::Invalid;
    }
    off += consumed;
    return DecodeStatus::Ok;
}

void append_var_u64(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    const auto a = module70::encode_u64(v);
    out.insert(out.end(), a.begin(), a.end());
}

[[nodiscard]] bool key_lt(const NodePos& a, const NodePos& b) {
    if (a.level != b.level) {
        return a.level < b.level;
    }
    return a.index < b.index;
}

} // namespace

std::vector<std::uint8_t> encode_multiproof(const MerkleMultiProof& p) {
    std::vector<std::uint8_t> out;
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    out.push_back(kVersion);

    append_var_u64(out, p.leaf_count);

    append_var_u64(out, static_cast<std::uint64_t>(p.leaves.size()));
    for (const auto& li : p.leaves) {
        append_var_u64(out, li.leaf_index);
        out.insert(out.end(), li.leaf_hash.begin(), li.leaf_hash.end());
    }

    append_var_u64(out, static_cast<std::uint64_t>(p.side_nodes.size()));
    for (const auto& sn : p.side_nodes) {
        append_var_u64(out, sn.pos.level);
        append_var_u64(out, sn.pos.index);
        out.insert(out.end(), sn.hash.begin(), sn.hash.end());
    }

    return out;
}

DecodeStatus decode_multiproof(std::span<const std::uint8_t> bytes,
                              MerkleMultiProof& out,
                              std::size_t& consumed,
                              const DecodeOptions& opt) {
    consumed = 0;
    if (bytes.empty()) {
        return DecodeStatus::Empty;
    }
    if (bytes.size() > opt.max_total_bytes) {
        return DecodeStatus::TooLong;
    }
    if (bytes.size() < 5) {
        return DecodeStatus::TooShort;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
        return DecodeStatus::BadMagic;
    }

    std::size_t off = 4;
    std::uint8_t ver = 0;
    if (!read_u8(bytes, off, ver)) {
        return DecodeStatus::TooShort;
    }
    if (ver != kVersion) {
        return DecodeStatus::BadVersion;
    }

    module70::DecodeOptions vopt;
    vopt.require_canonical = true;

    std::uint64_t leaf_count = 0;
    {
        const auto st = read_var_u64(bytes, off, leaf_count, vopt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
    }
    if (leaf_count == 0) {
        return DecodeStatus::Invalid;
    }

    const auto max_level = tree_depth(leaf_count);

    std::uint64_t leaf_items = 0;
    {
        const auto st = read_var_u64(bytes, off, leaf_items, vopt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
    }
    if (leaf_items == 0 || leaf_items > opt.max_leaves) {
        return DecodeStatus::Invalid;
    }

    out.leaf_count = leaf_count;
    out.leaves.clear();
    out.leaves.reserve(static_cast<std::size_t>(leaf_items));

    std::uint64_t prev_leaf = 0;
    bool have_prev_leaf = false;

    for (std::uint64_t i = 0; i < leaf_items; ++i) {
        std::uint64_t leaf_index = 0;
        {
            const auto st = read_var_u64(bytes, off, leaf_index, vopt);
            if (st != DecodeStatus::Ok) {
                return st;
            }
        }
        if (leaf_index >= leaf_count) {
            return DecodeStatus::Invalid;
        }
        if (have_prev_leaf && leaf_index <= prev_leaf) {
            return DecodeStatus::NonCanonical;
        }
        prev_leaf = leaf_index;
        have_prev_leaf = true;

        crypto::Hash256 h{};
        if (!read_hash256(bytes, off, h)) {
            return DecodeStatus::TooShort;
        }
        out.leaves.push_back(LeafItem{leaf_index, h});
    }

    std::uint64_t side_count = 0;
    {
        const auto st = read_var_u64(bytes, off, side_count, vopt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
    }
    if (side_count > opt.max_side_nodes) {
        return DecodeStatus::Invalid;
    }

    out.side_nodes.clear();
    out.side_nodes.reserve(static_cast<std::size_t>(side_count));

    NodePos prev_pos;
    bool have_prev_pos = false;

    for (std::uint64_t i = 0; i < side_count; ++i) {
        std::uint64_t level = 0;
        std::uint64_t index = 0;
        {
            const auto st = read_var_u64(bytes, off, level, vopt);
            if (st != DecodeStatus::Ok) {
                return st;
            }
        }
        {
            const auto st = read_var_u64(bytes, off, index, vopt);
            if (st != DecodeStatus::Ok) {
                return st;
            }
        }

        if (level > max_level) {
            return DecodeStatus::Invalid;
        }

        const auto ncount = node_count_at_level(leaf_count, level);
        if (index >= ncount) {
            return DecodeStatus::Invalid;
        }

        NodePos pos{level, index};
        if (have_prev_pos) {
            if (!key_lt(prev_pos, pos) && !(prev_pos.level == pos.level && prev_pos.index == pos.index)) {
                return DecodeStatus::NonCanonical;
            }
            if (prev_pos.level == pos.level && prev_pos.index == pos.index) {
                return DecodeStatus::NonCanonical;
            }
        }
        prev_pos = pos;
        have_prev_pos = true;

        for (const auto& li : out.leaves) {
            if (pos.level == 0 && pos.index == li.leaf_index) {
                return DecodeStatus::Invalid;
            }
        }

        crypto::Hash256 h{};
        if (!read_hash256(bytes, off, h)) {
            return DecodeStatus::TooShort;
        }
        out.side_nodes.push_back(SideNode{pos, h});
    }

    consumed = off;
    if (consumed != bytes.size()) {
        return DecodeStatus::NonCanonical;
    }

    return DecodeStatus::Ok;
}

std::optional<crypto::Hash256> verify_and_root(const MerkleMultiProof& p) {
    if (p.leaf_count == 0) {
        return std::nullopt;
    }
    if (p.leaves.empty()) {
        return std::nullopt;
    }

    std::unordered_map<Key, crypto::Hash256, KeyHash, KeyEq> nodes;

    for (const auto& li : p.leaves) {
        if (li.leaf_index >= p.leaf_count) {
            return std::nullopt;
        }
        const Key k{0, li.leaf_index};
        const auto it = nodes.find(k);
        if (it != nodes.end()) {
            if (it->second != li.leaf_hash) {
                return std::nullopt;
            }
        } else {
            nodes.emplace(k, li.leaf_hash);
        }
    }

    const auto max_level = tree_depth(p.leaf_count);

    for (const auto& sn : p.side_nodes) {
        if (sn.pos.level > max_level) {
            return std::nullopt;
        }
        const auto ncount = node_count_at_level(p.leaf_count, sn.pos.level);
        if (sn.pos.index >= ncount) {
            return std::nullopt;
        }
        const Key k{sn.pos.level, sn.pos.index};
        const auto it = nodes.find(k);
        if (it != nodes.end()) {
            if (it->second != sn.hash) {
                return std::nullopt;
            }
        } else {
            nodes.emplace(k, sn.hash);
        }
    }

    std::uint64_t level = 0;
    std::uint64_t ncount = p.leaf_count;

    while (ncount > 1) {
        const std::uint64_t parent_count = (ncount + 1) / 2;
        for (std::uint64_t pidx = 0; pidx < parent_count; ++pidx) {
            const std::uint64_t left_i = 2 * pidx;
            const std::uint64_t right_i = (left_i + 1 < ncount) ? (left_i + 1) : left_i;

            const Key kl{level, left_i};
            const Key kr{level, right_i};
            const auto itl = nodes.find(kl);
            const auto itr = nodes.find(kr);
            if (itl == nodes.end() || itr == nodes.end()) {
                continue;
            }

            const auto parent = merkle_parent(itl->second, itr->second);
            const Key kp{level + 1, pidx};
            const auto itp = nodes.find(kp);
            if (itp != nodes.end()) {
                if (itp->second != parent) {
                    return std::nullopt;
                }
            } else {
                nodes.emplace(kp, parent);
            }
        }

        ncount = parent_count;
        level += 1;
    }

    const Key rootk{level, 0};
    const auto it = nodes.find(rootk);
    if (it == nodes.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<MerkleMultiProof> build_from_leaves(std::span<const crypto::Hash256> full_leaves,
                                                 std::span<const std::uint64_t> target_leaf_indices) {
    if (full_leaves.empty()) {
        return std::nullopt;
    }

    std::vector<std::uint64_t> targets;
    targets.reserve(target_leaf_indices.size());
    for (const auto v : target_leaf_indices) {
        targets.push_back(v);
    }
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());

    if (targets.empty()) {
        return std::nullopt;
    }

    const auto leaf_count = static_cast<std::uint64_t>(full_leaves.size());
    for (const auto i : targets) {
        if (i >= leaf_count) {
            return std::nullopt;
        }
    }

    std::vector<std::vector<crypto::Hash256>> layers;
    layers.emplace_back(full_leaves.begin(), full_leaves.end());

    std::uint64_t ncount = leaf_count;
    std::uint64_t level = 0;
    while (ncount > 1) {
        const std::uint64_t parent_count = (ncount + 1) / 2;
        std::vector<crypto::Hash256> next;
        next.reserve(static_cast<std::size_t>(parent_count));

        for (std::uint64_t pidx = 0; pidx < parent_count; ++pidx) {
            const std::uint64_t left_i = 2 * pidx;
            const std::uint64_t right_i = (left_i + 1 < ncount) ? (left_i + 1) : left_i;
            next.push_back(merkle_parent(layers.back()[static_cast<std::size_t>(left_i)],
                                         layers.back()[static_cast<std::size_t>(right_i)]));
        }

        layers.push_back(std::move(next));
        ncount = parent_count;
        level += 1;
    }

    MerkleMultiProof out;
    out.leaf_count = leaf_count;

    out.leaves.clear();
    out.leaves.reserve(targets.size());
    for (const auto idx : targets) {
        out.leaves.push_back(LeafItem{idx, full_leaves[static_cast<std::size_t>(idx)]});
    }

    std::vector<SideNode> side;

    std::vector<std::uint64_t> need = targets;
    std::uint64_t cur_level = 0;

    while (layers[cur_level].size() > 1) {
        const std::uint64_t cur_n = static_cast<std::uint64_t>(layers[cur_level].size());
        std::vector<std::uint8_t> needed;
        needed.resize(static_cast<std::size_t>(cur_n), 0);
        for (const auto i : need) {
            if (i < cur_n) {
                needed[static_cast<std::size_t>(i)] = 1;
            }
        }

        std::vector<std::uint64_t> next_need;
        next_need.reserve(need.size());

        for (const auto i : need) {
            const auto sib = (i ^ 1ull);
            if (sib < cur_n) {
                if (needed[static_cast<std::size_t>(sib)] == 0) {
                    side.push_back(SideNode{NodePos{cur_level, sib}, layers[cur_level][static_cast<std::size_t>(sib)]});
                }
            }
            next_need.push_back(i / 2);
        }

        std::sort(next_need.begin(), next_need.end());
        next_need.erase(std::unique(next_need.begin(), next_need.end()), next_need.end());
        need = std::move(next_need);
        cur_level += 1;
    }

    std::sort(side.begin(), side.end(), [](const SideNode& a, const SideNode& b) {
        if (a.pos.level != b.pos.level) {
            return a.pos.level < b.pos.level;
        }
        return a.pos.index < b.pos.index;
    });
    side.erase(std::unique(side.begin(), side.end(), [](const SideNode& a, const SideNode& b) {
        return a.pos.level == b.pos.level && a.pos.index == b.pos.index;
    }), side.end());

    out.side_nodes = std::move(side);
    return out;
}

} // namespace randio::module81
