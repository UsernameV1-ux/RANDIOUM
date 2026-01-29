#include "rand/proof.hpp"

#include "rand/block_codec.hpp"
#include "rand/tx_codec.hpp"
#include "rand/varint.hpp"

#include <array>
#include <cstring>

namespace randio::module80 {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {static_cast<std::uint8_t>('R'), static_cast<std::uint8_t>('P'),
                                               static_cast<std::uint8_t>('R'), static_cast<std::uint8_t>('F')};
constexpr std::uint8_t kVersion = 1;

enum class Kind : std::uint8_t {
    TxInclusion = 1,
    Account = 2,
    ReceiptInclusion = 3,
};

[[nodiscard]] bool read_u8(std::span<const std::uint8_t> bytes, std::size_t& off, std::uint8_t& out) {
    if (off + 1 > bytes.size()) {
        return false;
    }
    out = bytes[off];
    off += 1;
    return true;
}

[[nodiscard]] bool read_bytes(std::span<const std::uint8_t> bytes, std::size_t& off, std::size_t n, std::span<const std::uint8_t>& out) {
    if (off + n > bytes.size()) {
        return false;
    }
    out = bytes.subspan(off, n);
    off += n;
    return true;
}

[[nodiscard]] bool read_hash256(std::span<const std::uint8_t> bytes, std::size_t& off, crypto::Hash256& out) {
    std::span<const std::uint8_t> s;
    if (!read_bytes(bytes, off, 32, s)) {
        return false;
    }
    std::copy(s.begin(), s.end(), out.begin());
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

[[nodiscard]] std::uint32_t read_u32_le(std::span<const std::uint8_t> bytes, const std::size_t off) {
    return static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8u) |
           (static_cast<std::uint32_t>(bytes[off + 2]) << 16u) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24u);
}

[[nodiscard]] std::uint64_t read_u64_le(std::span<const std::uint8_t> bytes, const std::size_t off) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(bytes[off + static_cast<std::size_t>(i)]) << (8u * i));
    }
    return v;
}

[[nodiscard]] bool decode_fixed_header(std::span<const std::uint8_t> bytes, std::size_t& off, std::uint8_t& kind_out) {
    if (bytes.size() < 6) {
        return false;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
        return false;
    }
    off = 4;
    std::uint8_t ver = 0;
    if (!read_u8(bytes, off, ver)) {
        return false;
    }
    if (ver != kVersion) {
        return false;
    }
    if (!read_u8(bytes, off, kind_out)) {
        return false;
    }
    return true;
}

void encode_fixed_header(std::vector<std::uint8_t>& out, const Kind kind) {
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    out.push_back(kVersion);
    out.push_back(static_cast<std::uint8_t>(kind));
}

[[nodiscard]] std::vector<std::uint8_t> serialize_account_bytes(const Account& a) {
    std::vector<std::uint8_t> out;
    out.reserve(16);
    append_u64_le(out, a.nonce);
    append_u64_le(out, a.balance);
    return out;
}

[[nodiscard]] bool validate_merkle_proof_shape(const MerkleProof& p) {
    if (p.leaf_count == 0) {
        return false;
    }
    if (p.leaf_index >= p.leaf_count) {
        return false;
    }
    if (p.siblings.size() != merkle_depth(p.leaf_count)) {
        return false;
    }
    return true;
}

} // namespace

std::size_t merkle_depth(const std::uint64_t leaf_count) {
    if (leaf_count <= 1) {
        return 0;
    }
    std::size_t d = 0;
    std::uint64_t n = 1;
    while (n < leaf_count) {
        n <<= 1u;
        d += 1;
    }
    return d;
}

crypto::Hash256 merkle_parent(const crypto::Hash256& left, const crypto::Hash256& right) {
    std::array<std::uint8_t, 64> buf{};
    std::copy(left.begin(), left.end(), buf.begin());
    std::copy(right.begin(), right.end(), buf.begin() + 32);
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

std::optional<crypto::Hash256> compute_merkle_root(const crypto::Hash256& leaf_hash, const MerkleProof& p) {
    if (!validate_merkle_proof_shape(p)) {
        return std::nullopt;
    }

    crypto::Hash256 cur = leaf_hash;
    std::uint64_t idx = p.leaf_index;

    for (std::size_t depth = 0; depth < p.siblings.size(); ++depth) {
        const auto& sib = p.siblings[depth];
        if ((idx & 1ull) == 0) {
            cur = merkle_parent(cur, sib);
        } else {
            cur = merkle_parent(sib, cur);
        }
        idx >>= 1u;
    }

    return cur;
}

bool verify_merkle_root(const crypto::Hash256& expected_root, const crypto::Hash256& leaf_hash, const MerkleProof& p) {
    const auto r = compute_merkle_root(leaf_hash, p);
    return r.has_value() && *r == expected_root;
}

std::vector<std::uint8_t> encode_merkle_proof(const MerkleProof& p) {
    std::vector<std::uint8_t> out;
    {
        const auto a = module70::encode_u64(p.leaf_index);
        out.insert(out.end(), a.begin(), a.end());
    }
    {
        const auto a = module70::encode_u64(p.leaf_count);
        out.insert(out.end(), a.begin(), a.end());
    }
    {
        const auto a = module70::encode_u64(static_cast<std::uint64_t>(p.siblings.size()));
        out.insert(out.end(), a.begin(), a.end());
    }
    for (const auto& h : p.siblings) {
        out.insert(out.end(), h.begin(), h.end());
    }
    return out;
}

DecodeStatus decode_merkle_proof(std::span<const std::uint8_t> bytes,
                                MerkleProof& out,
                                std::size_t& consumed,
                                const DecodeOptions& opt) {
    consumed = 0;
    if (bytes.empty()) {
        return DecodeStatus::Empty;
    }
    if (bytes.size() > opt.max_total_bytes) {
        return DecodeStatus::TooLong;
    }

    module70::DecodeOptions vopt;
    vopt.require_canonical = true;

    std::size_t off = 0;
    std::uint64_t leaf_index = 0;
    std::uint64_t leaf_count = 0;
    std::uint64_t sib_count = 0;

    {
        const auto st = read_var_u64(bytes, off, leaf_index, vopt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
    }
    {
        const auto st = read_var_u64(bytes, off, leaf_count, vopt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
    }
    {
        const auto st = read_var_u64(bytes, off, sib_count, vopt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
    }

    if (sib_count > opt.max_siblings) {
        return DecodeStatus::Invalid;
    }

    out.leaf_index = leaf_index;
    out.leaf_count = leaf_count;
    out.siblings.clear();
    out.siblings.reserve(static_cast<std::size_t>(sib_count));

    for (std::size_t i = 0; i < static_cast<std::size_t>(sib_count); ++i) {
        crypto::Hash256 h{};
        if (!read_hash256(bytes, off, h)) {
            return DecodeStatus::TooShort;
        }
        out.siblings.push_back(h);
    }

    consumed = off;

    if (!validate_merkle_proof_shape(out)) {
        return DecodeStatus::Invalid;
    }

    return DecodeStatus::Ok;
}

std::vector<std::uint8_t> encode_tx_inclusion_proof(const TxInclusionProof& p) {
    std::vector<std::uint8_t> out;
    encode_fixed_header(out, Kind::TxInclusion);

    const auto hb = module68::encode_header(p.header);
    out.insert(out.end(), hb.begin(), hb.end());

    const auto tb = module67::encode_tx(p.tx);
    append_u32_le(out, static_cast<std::uint32_t>(tb.size()));
    out.insert(out.end(), tb.begin(), tb.end());

    const auto mp = encode_merkle_proof(p.merkle);
    out.insert(out.end(), mp.begin(), mp.end());

    return out;
}

DecodeStatus decode_tx_inclusion_proof(std::span<const std::uint8_t> bytes,
                                      TxInclusionProof& out,
                                      std::size_t& consumed,
                                      const DecodeOptions& opt) {
    consumed = 0;
    if (bytes.empty()) {
        return DecodeStatus::Empty;
    }
    if (bytes.size() > opt.max_total_bytes) {
        return DecodeStatus::TooLong;
    }

    std::size_t off = 0;
    std::uint8_t kind = 0;
    if (!decode_fixed_header(bytes, off, kind)) {
        if (bytes.size() < 4) {
            return DecodeStatus::TooShort;
        }
        if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
            return DecodeStatus::BadMagic;
        }
        if (bytes.size() >= 5 && bytes[4] != kVersion) {
            return DecodeStatus::BadVersion;
        }
        return DecodeStatus::TooShort;
    }
    if (kind != static_cast<std::uint8_t>(Kind::TxInclusion)) {
        return DecodeStatus::BadKind;
    }

    if (off + module68::header_size_bytes() > bytes.size()) {
        return DecodeStatus::TooShort;
    }
    {
        const auto st = module68::decode_header(bytes.subspan(off, module68::header_size_bytes()), out.header);
        if (st != module68::DecodeStatus::Ok) {
            return DecodeStatus::Invalid;
        }
        off += module68::header_size_bytes();
    }

    if (off + 4 > bytes.size()) {
        return DecodeStatus::TooShort;
    }
    const auto tlen = static_cast<std::size_t>(read_u32_le(bytes, off));
    off += 4;

    if (tlen > opt.max_tx_bytes) {
        return DecodeStatus::Invalid;
    }
    if (off + tlen > bytes.size()) {
        return DecodeStatus::TooShort;
    }

    {
        module67::DecodeOptions txopt;
        txopt.max_payload_bytes = opt.max_tx_bytes;
        const auto st = module67::decode_tx(bytes.subspan(off, tlen), out.tx, txopt);
        if (st != module67::DecodeStatus::Ok) {
            return DecodeStatus::Invalid;
        }
        off += tlen;
    }

    {
        std::size_t mp_consumed = 0;
        const auto st = decode_merkle_proof(bytes.subspan(off), out.merkle, mp_consumed, opt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
        off += mp_consumed;
    }

    consumed = off;
    if (consumed != bytes.size()) {
        return DecodeStatus::NonCanonical;
    }

    return DecodeStatus::Ok;
}

std::vector<std::uint8_t> encode_account_proof(const AccountProof& p) {
    std::vector<std::uint8_t> out;
    encode_fixed_header(out, Kind::Account);

    {
        const auto a = module70::encode_u64(p.height);
        out.insert(out.end(), a.begin(), a.end());
    }
    out.insert(out.end(), p.state_root.begin(), p.state_root.end());

    {
        const auto a = module70::encode_u64(static_cast<std::uint64_t>(p.id.size()));
        out.insert(out.end(), a.begin(), a.end());
    }
    out.insert(out.end(), p.id.begin(), p.id.end());

    const auto ab = serialize_account_bytes(p.account);
    out.insert(out.end(), ab.begin(), ab.end());

    const auto mp = encode_merkle_proof(p.merkle);
    out.insert(out.end(), mp.begin(), mp.end());

    return out;
}

DecodeStatus decode_account_proof(std::span<const std::uint8_t> bytes,
                                 AccountProof& out,
                                 std::size_t& consumed,
                                 const DecodeOptions& opt) {
    consumed = 0;
    if (bytes.empty()) {
        return DecodeStatus::Empty;
    }
    if (bytes.size() > opt.max_total_bytes) {
        return DecodeStatus::TooLong;
    }

    std::size_t off = 0;
    std::uint8_t kind = 0;
    if (!decode_fixed_header(bytes, off, kind)) {
        if (bytes.size() < 4) {
            return DecodeStatus::TooShort;
        }
        if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
            return DecodeStatus::BadMagic;
        }
        if (bytes.size() >= 5 && bytes[4] != kVersion) {
            return DecodeStatus::BadVersion;
        }
        return DecodeStatus::TooShort;
    }
    if (kind != static_cast<std::uint8_t>(Kind::Account)) {
        return DecodeStatus::BadKind;
    }

    module70::DecodeOptions vopt;
    vopt.require_canonical = true;

    {
        std::uint64_t h = 0;
        const auto st = read_var_u64(bytes, off, h, vopt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
        out.height = h;
    }

    if (!read_hash256(bytes, off, out.state_root)) {
        return DecodeStatus::TooShort;
    }

    std::uint64_t id_len = 0;
    {
        const auto st = read_var_u64(bytes, off, id_len, vopt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
    }
    if (id_len == 0 || id_len > opt.max_id_bytes) {
        return DecodeStatus::Invalid;
    }

    {
        std::span<const std::uint8_t> s;
        if (!read_bytes(bytes, off, static_cast<std::size_t>(id_len), s)) {
            return DecodeStatus::TooShort;
        }
        out.id.assign(reinterpret_cast<const char*>(s.data()), reinterpret_cast<const char*>(s.data() + s.size()));
    }

    if (off + 16 > bytes.size()) {
        return DecodeStatus::TooShort;
    }
    out.account.nonce = read_u64_le(bytes, off);
    out.account.balance = read_u64_le(bytes, off + 8);
    off += 16;

    {
        std::size_t mp_consumed = 0;
        const auto st = decode_merkle_proof(bytes.subspan(off), out.merkle, mp_consumed, opt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
        off += mp_consumed;
    }

    consumed = off;
    if (consumed != bytes.size()) {
        return DecodeStatus::NonCanonical;
    }

    return DecodeStatus::Ok;
}

std::vector<std::uint8_t> encode_receipt_inclusion_proof(const ReceiptInclusionProof& p) {
    std::vector<std::uint8_t> out;
    encode_fixed_header(out, Kind::ReceiptInclusion);

    const auto hb = module68::encode_header(p.header);
    out.insert(out.end(), hb.begin(), hb.end());

    out.insert(out.end(), p.txid.begin(), p.txid.end());
    out.push_back(p.applied ? 1u : 0u);
    out.insert(out.end(), p.receipt_root.begin(), p.receipt_root.end());

    const auto mp = encode_merkle_proof(p.merkle);
    out.insert(out.end(), mp.begin(), mp.end());

    return out;
}

DecodeStatus decode_receipt_inclusion_proof(std::span<const std::uint8_t> bytes,
                                           ReceiptInclusionProof& out,
                                           std::size_t& consumed,
                                           const DecodeOptions& opt) {
    consumed = 0;
    if (bytes.empty()) {
        return DecodeStatus::Empty;
    }
    if (bytes.size() > opt.max_total_bytes) {
        return DecodeStatus::TooLong;
    }

    std::size_t off = 0;
    std::uint8_t kind = 0;
    if (!decode_fixed_header(bytes, off, kind)) {
        if (bytes.size() < 4) {
            return DecodeStatus::TooShort;
        }
        if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
            return DecodeStatus::BadMagic;
        }
        if (bytes.size() >= 5 && bytes[4] != kVersion) {
            return DecodeStatus::BadVersion;
        }
        return DecodeStatus::TooShort;
    }
    if (kind != static_cast<std::uint8_t>(Kind::ReceiptInclusion)) {
        return DecodeStatus::BadKind;
    }

    if (off + module68::header_size_bytes() > bytes.size()) {
        return DecodeStatus::TooShort;
    }
    {
        const auto st = module68::decode_header(bytes.subspan(off, module68::header_size_bytes()), out.header);
        if (st != module68::DecodeStatus::Ok) {
            return DecodeStatus::Invalid;
        }
        off += module68::header_size_bytes();
    }

    if (!read_hash256(bytes, off, out.txid)) {
        return DecodeStatus::TooShort;
    }

    std::uint8_t applied = 0;
    if (!read_u8(bytes, off, applied)) {
        return DecodeStatus::TooShort;
    }
    if (applied != 0 && applied != 1) {
        return DecodeStatus::NonCanonical;
    }
    out.applied = (applied == 1);

    if (!read_hash256(bytes, off, out.receipt_root)) {
        return DecodeStatus::TooShort;
    }

    {
        std::size_t mp_consumed = 0;
        const auto st = decode_merkle_proof(bytes.subspan(off), out.merkle, mp_consumed, opt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
        off += mp_consumed;
    }

    consumed = off;
    if (consumed != bytes.size()) {
        return DecodeStatus::NonCanonical;
    }

    return DecodeStatus::Ok;
}

bool verify_tx_inclusion(const TxInclusionProof& p) {
    const auto leaf = txid(p.tx);
    return verify_merkle_root(p.header.merkle_root, leaf, p.merkle);
}

crypto::Hash256 account_leaf_hash(const std::string_view id, const Account& a) {
    const auto ab = serialize_account_bytes(a);

    std::vector<std::uint8_t> buf;
    buf.reserve(1 + id.size() + ab.size());
    buf.push_back(0xA1);
    buf.insert(buf.end(), id.begin(), id.end());
    buf.insert(buf.end(), ab.begin(), ab.end());

    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

bool verify_account_proof(const AccountProof& p) {
    const auto leaf = account_leaf_hash(p.id, p.account);
    return verify_merkle_root(p.state_root, leaf, p.merkle);
}

crypto::Hash256 receipt_leaf_hash(const crypto::Hash256& txid_in, const bool applied) {
    if (applied) {
        return txid_in;
    }
    std::array<std::uint8_t, 33> buf{};
    std::copy(txid_in.begin(), txid_in.end(), buf.begin());
    buf[32] = 0u;
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

bool verify_receipt_inclusion(const ReceiptInclusionProof& p) {
    if (!p.applied) {
        return false;
    }
    if (p.receipt_root != p.header.merkle_root) {
        return false;
    }
    const auto leaf = receipt_leaf_hash(p.txid, p.applied);
    return verify_merkle_root(p.receipt_root, leaf, p.merkle);
}

} // namespace randio::module80
