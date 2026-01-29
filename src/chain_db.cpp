#include "rand/chain_db.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace randio {
namespace {

constexpr std::string_view kTipHeightKey = "meta:tip_height";
constexpr std::string_view kTipHashKey = "meta:tip_hash";

std::string height_key(const std::uint64_t height) {
    return "hdr:height:" + std::to_string(height);
}

std::string body_key(const std::uint64_t height) {
    return "blk:body:" + std::to_string(height);
}

std::string state_root_key(const std::uint64_t height) {
    return "state:root:" + std::to_string(height);
}

std::string hash_height_key(const crypto::Hash256& h) {
    return "hdr:hash:" + crypto::to_hex(h);
}

bool is_all_zero(const crypto::Hash256& h) {
    for (const auto b : h) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

void append_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

std::uint32_t read_u32_le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
           (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
}

std::uint64_t read_u64_le(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
    }
    return v;
}

std::optional<Transaction> parse_tx_bytes(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 4 + 8 + 8 + 4) {
        return std::nullopt;
    }
    const std::uint8_t* p = bytes.data();
    const auto ver = read_u32_le(p);
    p += 4;
    const auto nonce = read_u64_le(p);
    p += 8;
    const auto fee = read_u64_le(p);
    p += 8;
    const auto plen = read_u32_le(p);
    p += 4;
    if (static_cast<std::size_t>(p - bytes.data()) + static_cast<std::size_t>(plen) != bytes.size()) {
        return std::nullopt;
    }
    Transaction tx;
    tx.version = ver;
    tx.nonce = nonce;
    tx.fee = fee;
    tx.payload.assign(p, p + plen);
    return tx;
}

}

ChainDB::ChainDB(std::filesystem::path data_dir, Options opt)
    : data_dir_(std::move(data_dir)), opt_(opt), storage_(data_dir_, opt_.storage) {}

bool ChainDB::open() {
    return storage_.open();
}

std::vector<std::uint8_t> ChainDB::u64_le(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

std::optional<std::uint64_t> ChainDB::parse_u64_le(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() != 8) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(bytes[static_cast<std::size_t>(i)]) << (8u * i));
    }
    return v;
}

bool ChainDB::has_tip_() const {
    return storage_.get(kTipHeightKey).has_value() && storage_.get(kTipHashKey).has_value();
}

std::optional<std::uint64_t> ChainDB::tip_height_() const {
    const auto v = storage_.get(kTipHeightKey);
    if (!v) {
        return std::nullopt;
    }
    return parse_u64_le(*v);
}

std::optional<crypto::Hash256> ChainDB::tip_hash_() const {
    const auto v = storage_.get(kTipHashKey);
    if (!v || v->size() != 32) {
        return std::nullopt;
    }
    crypto::Hash256 h{};
    std::copy(v->begin(), v->end(), h.begin());
    return h;
}

bool ChainDB::set_tip_(const std::uint64_t height, const crypto::Hash256& hash) {
    auto b = storage_.begin_batch();
    storage_.put(b, std::string(kTipHeightKey), u64_le(height));
    storage_.put(b, std::string(kTipHashKey), std::vector<std::uint8_t>(hash.begin(), hash.end()));
    return storage_.commit(b);
}

std::optional<BlockHeader> ChainDB::load_header_(const std::uint64_t height) const {
    const auto v = storage_.get(height_key(height));
    if (!v) {
        return std::nullopt;
    }

    const auto& bytes = *v;
    if (bytes.size() != 4 + 8 + 32 + 32 + 8 + 8) {
        return std::nullopt;
    }

    BlockHeader h;

    auto dec_u32 = [](const std::uint8_t* p) -> std::uint32_t {
        return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
               (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
    };

    auto dec_u64 = [](const std::uint8_t* p) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
        }
        return v;
    };

    const std::uint8_t* p = bytes.data();
    h.version = dec_u32(p);
    p += 4;
    h.height = dec_u64(p);
    p += 8;
    std::copy(p, p + 32, h.prev_block.begin());
    p += 32;
    std::copy(p, p + 32, h.merkle_root.begin());
    p += 32;
    h.timestamp_unix_seconds = dec_u64(p);
    p += 8;
    h.nonce = dec_u64(p);

    return h;
}

std::optional<BlockHeader> ChainDB::header_by_height(const std::uint64_t height) const {
    return load_header_(height);
}

void ChainDB::store_block_body_(Storage::Batch& batch, const std::uint64_t height, const std::vector<Transaction>& txs) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + txs.size() * 16);
    append_u32_le(out, static_cast<std::uint32_t>(txs.size()));
    for (const auto& tx : txs) {
        const auto tb = serialize_tx(tx);
        append_u32_le(out, static_cast<std::uint32_t>(tb.size()));
        out.insert(out.end(), tb.begin(), tb.end());
    }
    storage_.put(batch, body_key(height), std::move(out));
}

std::optional<std::vector<Transaction>> ChainDB::load_block_body_(const std::uint64_t height) const {
    const auto v = storage_.get(body_key(height));
    if (!v) {
        return std::nullopt;
    }
    const auto& bytes = *v;
    if (bytes.size() < 4) {
        return std::nullopt;
    }
    std::size_t off = 0;
    const auto count = read_u32_le(bytes.data());
    off += 4;

    std::vector<Transaction> txs;
    txs.reserve(count);

    for (std::uint32_t i = 0; i < count; ++i) {
        if (off + 4 > bytes.size()) {
            return std::nullopt;
        }
        const auto len = read_u32_le(bytes.data() + off);
        off += 4;
        if (off + static_cast<std::size_t>(len) > bytes.size()) {
            return std::nullopt;
        }
        std::vector<std::uint8_t> tb(bytes.begin() + static_cast<std::ptrdiff_t>(off),
                                     bytes.begin() + static_cast<std::ptrdiff_t>(off + static_cast<std::size_t>(len)));
        off += static_cast<std::size_t>(len);
        const auto tx = parse_tx_bytes(tb);
        if (!tx) {
            return std::nullopt;
        }
        txs.push_back(*tx);
    }

    if (off != bytes.size()) {
        return std::nullopt;
    }
    return txs;
}

std::optional<Block> ChainDB::block_by_height(const std::uint64_t height) const {
    const auto hdr = load_header_(height);
    if (!hdr) {
        return std::nullopt;
    }
    const auto txs = load_block_body_(height);
    if (!txs) {
        return std::nullopt;
    }
    Block b;
    b.header = *hdr;
    b.transactions = *txs;
    return b;
}

std::optional<crypto::Hash256> ChainDB::state_root_by_height(const std::uint64_t height) const {
    const auto v = storage_.get(state_root_key(height));
    if (!v || v->size() != 32) {
        return std::nullopt;
    }
    crypto::Hash256 h{};
    std::copy(v->begin(), v->end(), h.begin());
    return h;
}

bool ChainDB::verify_bootstrap(const std::uint64_t height,
                              const crypto::Hash256& expected_block_hash,
                              const crypto::Hash256& expected_state_root) const {
    const auto hdr = header_by_height(height);
    if (!hdr) {
        return false;
    }
    if (block_hash(*hdr) != expected_block_hash) {
        return false;
    }
    const auto sr = state_root_by_height(height);
    if (!sr) {
        return false;
    }
    if (*sr != expected_state_root) {
        return false;
    }
    return true;
}

bool ChainDB::set_state_root(const std::uint64_t height, const crypto::Hash256& root) {
    auto b = storage_.begin_batch();
    storage_.put(b, state_root_key(height), std::vector<std::uint8_t>(root.begin(), root.end()));
    return storage_.commit(b);
}

std::optional<ChainDB::Tip> ChainDB::tip() const {
    if (!has_tip_()) {
        return std::nullopt;
    }

    const auto th = tip_height_();
    const auto hh = tip_hash_();
    if (!th || !hh) {
        return std::nullopt;
    }

    const auto hdr = load_header_(*th);
    if (!hdr) {
        return std::nullopt;
    }

    Tip t;
    t.height = *th;
    t.hash = *hh;
    t.header = *hdr;
    return t;
}

void ChainDB::store_header_(Storage::Batch& batch, const BlockHeader& h, const crypto::Hash256& hash) {
    const auto bytes = serialize_block_header(h);
    storage_.put(batch, height_key(h.height), bytes);
    storage_.put(batch, hash_height_key(hash), u64_le(h.height));
}

bool ChainDB::validate_genesis_(const Block& b) const {
    if (b.header.height != 0) {
        return false;
    }
    if (!is_all_zero(b.header.prev_block)) {
        return false;
    }
    if (!validate_block(b, opt_.validation)) {
        return false;
    }
    return true;
}

bool ChainDB::validate_next_(const Block& b, const BlockHeader& prev) const {
    if (b.header.height != prev.height + 1) {
        return false;
    }
    const auto prev_hash = block_hash(prev);
    if (b.header.prev_block != prev_hash) {
        return false;
    }
    if (b.header.timestamp_unix_seconds < prev.timestamp_unix_seconds) {
        return false;
    }
    if (!validate_block(b, opt_.validation)) {
        return false;
    }
    return true;
}

bool ChainDB::put_genesis(const Block& genesis) {
    if (has_tip_()) {
        return false;
    }
    if (!validate_genesis_(genesis)) {
        return false;
    }

    const auto hash = block_hash(genesis.header);

    auto b = storage_.begin_batch();
    store_header_(b, genesis.header, hash);
    store_block_body_(b, genesis.header.height, genesis.transactions);
    storage_.put(b, std::string(kTipHeightKey), u64_le(0));
    storage_.put(b, std::string(kTipHashKey), std::vector<std::uint8_t>(hash.begin(), hash.end()));
    return storage_.commit(b);
}

bool ChainDB::add_block(const Block& b) {
    const auto t = tip();
    if (!t) {
        return false;
    }

    if (!validate_next_(b, t->header)) {
        return false;
    }

    const auto hash = block_hash(b.header);

    auto batch = storage_.begin_batch();
    store_header_(batch, b.header, hash);
    store_block_body_(batch, b.header.height, b.transactions);
    storage_.put(batch, std::string(kTipHeightKey), u64_le(b.header.height));
    storage_.put(batch, std::string(kTipHashKey), std::vector<std::uint8_t>(hash.begin(), hash.end()));
    return storage_.commit(batch);
}

}
