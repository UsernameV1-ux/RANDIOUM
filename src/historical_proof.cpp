#include "rand/historical_proof.hpp"

#include "rand/block_codec.hpp"
#include "rand/chain_db.hpp"
#include "rand/exec_engine.hpp"
#include "rand/hex.hpp"
#include "rand/proof.hpp"
#include "rand/sha256.hpp"
#include "rand/storage.hpp"
#include "rand/tx_codec.hpp"
#include "rand/u64_codec.hpp"
#include "rand/varint.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace randio::module88 {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {static_cast<std::uint8_t>('R'), static_cast<std::uint8_t>('H'),
                                               static_cast<std::uint8_t>('P'), static_cast<std::uint8_t>('F')};
constexpr std::uint8_t kVersion = 1;

void append_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

[[nodiscard]] bool read_u8(std::span<const std::uint8_t> bytes, std::size_t& off, std::uint8_t& out) {
    if (off + 1 > bytes.size()) {
        return false;
    }
    out = bytes[off];
    off += 1;
    return true;
}

[[nodiscard]] bool read_u32_le(std::span<const std::uint8_t> bytes, std::size_t& off, std::uint32_t& out) {
    if (off + 4 > bytes.size()) {
        return false;
    }
    out = static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8u) |
          (static_cast<std::uint32_t>(bytes[off + 2]) << 16u) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24u);
    off += 4;
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

[[nodiscard]] std::optional<std::vector<std::string>> decode_index_bytes(const std::vector<std::uint8_t>& bytes) {
    auto read_u32 = [](const std::uint8_t* p) -> std::uint32_t {
        return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
               (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
    };

    if (bytes.size() < 4) {
        return std::nullopt;
    }

    std::size_t off = 0;
    const auto count = read_u32(bytes.data());
    off += 4;

    std::vector<std::string> idx;
    idx.reserve(count);

    for (std::uint32_t i = 0; i < count; ++i) {
        if (off + 4 > bytes.size()) {
            return std::nullopt;
        }
        const auto len = read_u32(bytes.data() + off);
        off += 4;

        if (off + len > bytes.size()) {
            return std::nullopt;
        }

        std::string s(reinterpret_cast<const char*>(bytes.data() + off),
                      reinterpret_cast<const char*>(bytes.data() + off + len));
        off += len;
        idx.push_back(std::move(s));
    }

    if (off != bytes.size()) {
        return std::nullopt;
    }

    return idx;
}

struct StateLeaves final {
    std::vector<crypto::Hash256> leaves;
    std::optional<std::uint64_t> account_leaf_index;
    std::optional<Account> account;
};

[[nodiscard]] std::optional<StateLeaves> build_state_leaves(Storage& stor, std::string_view want_account_id) {
    auto load_index = [&](std::string_view key) -> std::optional<std::vector<std::string>> {
        const auto v = stor.get(key);
        if (!v) {
            return std::vector<std::string>{};
        }
        auto decoded = decode_index_bytes(*v);
        if (!decoded) {
            return std::nullopt;
        }
        std::sort(decoded->begin(), decoded->end());
        decoded->erase(std::unique(decoded->begin(), decoded->end()), decoded->end());
        return *decoded;
    };

    const auto aidx = load_index("state:index");
    const auto cidx = load_index("state:contracts");
    const auto sidx = load_index("state:storage");
    if (!aidx || !cidx || !sidx) {
        return std::nullopt;
    }

    StateLeaves out;

    out.leaves.reserve(aidx->size() + cidx->size() + sidx->size() + 8);

    auto read_u64 = [](const std::uint8_t* p) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
        }
        return v;
    };

    for (const auto& id : *aidx) {
        const auto raw = stor.get("acct:" + id);
        if (!raw || raw->size() != 16) {
            continue;
        }

        Account a;
        a.nonce = read_u64(raw->data());
        a.balance = read_u64(raw->data() + 8);

        if (id == want_account_id) {
            out.account_leaf_index = static_cast<std::uint64_t>(out.leaves.size());
            out.account = a;
        }

        out.leaves.push_back(module80::account_leaf_hash(id, a));
    }

    auto push_u64_leaf = [&](const std::uint8_t tag, const std::string_view key) {
        const auto v = stor.get(std::string(key));
        std::vector<std::uint8_t> buf;
        if (v) {
            buf.reserve(1 + v->size());
            buf.push_back(tag);
            buf.insert(buf.end(), v->begin(), v->end());
        } else {
            buf.reserve(1);
            buf.push_back(tag);
        }
        out.leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    };

    push_u64_leaf(0xE3, "fees:base_fee_per_gas");
    push_u64_leaf(0xE4, "fees:base_fee_min");
    push_u64_leaf(0xE5, "fees:base_fee_max");
    push_u64_leaf(0xE6, "fees:target_gas_per_block");
    push_u64_leaf(0xE7, "fees:max_gas_per_block");
    push_u64_leaf(0xE8, "fees:base_fee_adjust_rate_ppm");
    push_u64_leaf(0xE9, "fees:tip_pool_total");

    for (const auto& ch : *cidx) {
        const auto code = stor.get("code:" + ch);
        if (!code) {
            continue;
        }
        const auto chash = crypto::sha256(std::span<const std::uint8_t>(code->data(), code->size()));
        std::vector<std::uint8_t> buf;
        buf.reserve(1 + ch.size() + 32);
        buf.push_back(0xC1);
        buf.insert(buf.end(), ch.begin(), ch.end());
        buf.insert(buf.end(), chash.begin(), chash.end());
        out.leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    }

    for (const auto& se : *sidx) {
        const auto val = stor.get("stor:" + se);
        if (!val) {
            continue;
        }
        const auto vhash = crypto::sha256(std::span<const std::uint8_t>(val->data(), val->size()));
        std::vector<std::uint8_t> buf;
        buf.reserve(1 + se.size() + 32);
        buf.push_back(0xD1);
        buf.insert(buf.end(), se.begin(), se.end());
        buf.insert(buf.end(), vhash.begin(), vhash.end());
        out.leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    }

    {
        const auto v = stor.get("econ:minted_total");
        std::vector<std::uint8_t> buf;
        if (v) {
            buf.reserve(1 + v->size());
            buf.push_back(0xE1);
            buf.insert(buf.end(), v->begin(), v->end());
        } else {
            buf.reserve(1);
            buf.push_back(0xE1);
        }
        out.leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    }
    {
        const auto v = stor.get("econ:burned_total");
        std::vector<std::uint8_t> buf;
        if (v) {
            buf.reserve(1 + v->size());
            buf.push_back(0xE2);
            buf.insert(buf.end(), v->begin(), v->end());
        } else {
            buf.reserve(1);
            buf.push_back(0xE2);
        }
        out.leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    }

    return out;
}

[[nodiscard]] std::optional<crypto::Hash256> merkle_root_hashes(std::vector<crypto::Hash256> layer) {
    if (layer.empty()) {
        return std::nullopt;
    }

    while (layer.size() > 1) {
        std::vector<crypto::Hash256> next;
        next.reserve((layer.size() + 1) / 2);

        for (std::size_t i = 0; i < layer.size(); i += 2) {
            const auto& left = layer[i];
            const auto& right = (i + 1 < layer.size()) ? layer[i + 1] : layer[i];
            next.push_back(module80::merkle_parent(left, right));
        }

        layer = std::move(next);
    }

    return layer[0];
}

[[nodiscard]] std::optional<std::string> read_all_text(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        return std::nullopt;
    }
    in.seekg(0, std::ios::end);
    const auto sz = in.tellg();
    if (sz < 0) {
        return std::nullopt;
    }
    in.seekg(0, std::ios::beg);
    std::string out;
    out.resize(static_cast<std::size_t>(sz));
    if (!out.empty()) {
        in.read(out.data(), static_cast<std::streamsize>(out.size()));
    }
    if (!in.good() && !in.eof()) {
        return std::nullopt;
    }
    return out;
}

[[nodiscard]] std::optional<std::uint64_t> parse_json_u64_field(std::string_view s, std::string_view key) {
    const auto k = std::string("\"") + std::string(key) + "\"";
    const auto pos = s.find(k);
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }
    const auto colon = s.find(':', pos + k.size());
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t i = colon + 1;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) {
        ++i;
    }
    std::size_t j = i;
    while (j < s.size() && (s[j] >= '0' && s[j] <= '9')) {
        ++j;
    }
    if (j == i) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    {
        module73::DecodeOptions opt;
        opt.require_canonical = true;
        if (module73::parse_u64(s.substr(i, j - i), v, opt) != module73::DecodeStatus::Ok) {
            return std::nullopt;
        }
    }
    return v;
}

[[nodiscard]] std::optional<std::vector<std::pair<std::string, std::uint64_t>>> parse_genesis_allocations(std::string_view s) {
    std::vector<std::pair<std::string, std::uint64_t>> out;
    std::size_t pos = 0;
    for (;;) {
        const auto idk = s.find("\"id\"", pos);
        if (idk == std::string_view::npos) {
            break;
        }
        const auto colon1 = s.find(':', idk);
        if (colon1 == std::string_view::npos) {
            return std::nullopt;
        }
        const auto q1 = s.find('"', colon1 + 1);
        if (q1 == std::string_view::npos) {
            return std::nullopt;
        }
        const auto q2 = s.find('"', q1 + 1);
        if (q2 == std::string_view::npos) {
            return std::nullopt;
        }
        const auto id = std::string(s.substr(q1 + 1, q2 - (q1 + 1)));

        const auto amt_k = s.find("\"amount\"", q2);
        if (amt_k == std::string_view::npos) {
            return std::nullopt;
        }
        const auto colon2 = s.find(':', amt_k);
        if (colon2 == std::string_view::npos) {
            return std::nullopt;
        }
        std::size_t i = colon2 + 1;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) {
            ++i;
        }
        std::size_t j = i;
        while (j < s.size() && (s[j] >= '0' && s[j] <= '9')) {
            ++j;
        }
        if (j == i) {
            return std::nullopt;
        }
        std::uint64_t amt = 0;
        {
            module73::DecodeOptions opt;
            opt.require_canonical = true;
            if (module73::parse_u64(s.substr(i, j - i), amt, opt) != module73::DecodeStatus::Ok) {
                return std::nullopt;
            }
        }

        out.emplace_back(id, amt);
        pos = j;
    }
    return out;
}

[[nodiscard]] std::optional<GlobalState> replay_state_to_height(const std::filesystem::path& data_dir,
                                                               const std::uint64_t height,
                                                               const std::uint64_t max_supply,
                                                               const std::vector<std::pair<std::string, std::uint64_t>>& alloc,
                                                               const ChainDB& src_db) {
    std::uint64_t total = 0;
    for (const auto& [_, amt] : alloc) {
        total += amt;
    }

    const auto tmp_base = std::filesystem::temp_directory_path() /
                          ("randium_hist_state_" + crypto::to_hex(crypto::sha256(data_dir.string() + ":" + std::to_string(height))));

    std::error_code ec;
    std::filesystem::remove_all(tmp_base, ec);
    ec.clear();
    std::filesystem::create_directories(tmp_base, ec);
    if (ec) {
        return std::nullopt;
    }

    GlobalState::Options gs_opt;
    gs_opt.storage.schema_version = 1;
    gs_opt.max_supply = max_supply;

    GlobalState st(tmp_base / "state", gs_opt);
    if (!st.open()) {
        return std::nullopt;
    }

    StateDelta gd;
    if (!st.init_genesis_supply(total, alloc, gd)) {
        return std::nullopt;
    }

    if (height == 0) {
        return st;
    }

    TransactionScheduler sched(TransactionScheduler::Options{1000, 4 * 1024 * 1024});
    DeterministicExecutor ex(DeterministicExecutor::Options{1});

    for (std::uint64_t h = 1; h <= height; ++h) {
        StateDelta ud;
        (void)st.apply_scheduled_upgrade(h, ud);

        const auto blk = src_db.block_by_height(h);
        if (!blk) {
            return std::nullopt;
        }

        Mempool::Options mp_opt;
        mp_opt.max_tx_version = static_cast<std::uint32_t>(st.protocol_version());
        Mempool mp(mp_opt);

        for (const auto& tx : blk->transactions) {
            (void)mp.add(tx);
        }

        const auto batch = sched.build_batch(mp);
        const auto plan = ExecutionPlanner::plan(batch);
        (void)ex.execute(st, plan, h);

        const auto expect_sr = src_db.state_root_by_height(h);
        if (!expect_sr) {
            return std::nullopt;
        }
        if (st.state_root() != *expect_sr) {
            return std::nullopt;
        }
    }

    return st;
}

} // namespace

std::vector<std::uint8_t> encode_historical_proof(const HistoricalProof& p) {
    std::vector<std::uint8_t> out;
    out.insert(out.end(), kMagic.begin(), kMagic.end());
    out.push_back(kVersion);
    out.push_back(static_cast<std::uint8_t>(p.kind));

    append_var_u64(out, p.proof_height);

    const auto hb = module68::encode_header(p.header);
    out.insert(out.end(), hb.begin(), hb.end());

    out.insert(out.end(), p.block_hash.begin(), p.block_hash.end());
    out.insert(out.end(), p.state_root_at_height.begin(), p.state_root_at_height.end());

    if (p.kind == Kind::Account) {
        append_var_u64(out, static_cast<std::uint64_t>(p.account_id.size()));
        out.insert(out.end(), p.account_id.begin(), p.account_id.end());

        std::vector<std::uint8_t> acc;
        acc.reserve(16);
        for (int i = 0; i < 8; ++i) {
            acc.push_back(static_cast<std::uint8_t>((p.account.nonce >> (8u * i)) & 0xFFu));
        }
        for (int i = 0; i < 8; ++i) {
            acc.push_back(static_cast<std::uint8_t>((p.account.balance >> (8u * i)) & 0xFFu));
        }
        out.insert(out.end(), acc.begin(), acc.end());
    } else if (p.kind == Kind::Tx) {
        const auto tb = module67::encode_tx(p.tx);
        append_u32_le(out, static_cast<std::uint32_t>(tb.size()));
        out.insert(out.end(), tb.begin(), tb.end());
        append_var_u64(out, p.tx_index);
    } else {
        out.insert(out.end(), p.txid.begin(), p.txid.end());
        out.push_back(static_cast<std::uint8_t>(p.applied ? 1 : 0));
        append_var_u64(out, p.tx_index);
    }

    const auto mp = module81::encode_multiproof(p.multiproof);
    out.insert(out.end(), mp.begin(), mp.end());

    return out;
}

DecodeStatus decode_historical_proof(std::span<const std::uint8_t> bytes,
                                    HistoricalProof& out,
                                    std::size_t& consumed,
                                    const DecodeOptions& opt) {
    consumed = 0;
    if (bytes.empty()) {
        return DecodeStatus::Empty;
    }
    if (bytes.size() > opt.max_total_bytes) {
        return DecodeStatus::TooLong;
    }
    if (bytes.size() < 6) {
        return DecodeStatus::TooShort;
    }
    if (!std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
        return DecodeStatus::BadMagic;
    }
    if (bytes[4] != kVersion) {
        return DecodeStatus::BadVersion;
    }

    std::size_t off = 5;
    std::uint8_t kind = 0;
    if (!read_u8(bytes, off, kind)) {
        return DecodeStatus::TooShort;
    }

    if (kind != static_cast<std::uint8_t>(Kind::Account) && kind != static_cast<std::uint8_t>(Kind::Tx) &&
        kind != static_cast<std::uint8_t>(Kind::Receipt)) {
        return DecodeStatus::BadKind;
    }

    module70::DecodeOptions vopt;
    vopt.require_canonical = true;

    std::uint64_t height = 0;
    {
        const auto st = read_var_u64(bytes, off, height, vopt);
        if (st != DecodeStatus::Ok) {
            return st;
        }
    }

    if (off + module68::header_size_bytes() > bytes.size()) {
        return DecodeStatus::TooShort;
    }

    BlockHeader hdr;
    {
        const auto st = module68::decode_header(bytes.subspan(off, module68::header_size_bytes()), hdr);
        if (st != module68::DecodeStatus::Ok) {
            return DecodeStatus::Invalid;
        }
        off += module68::header_size_bytes();
    }

    crypto::Hash256 bh{};
    crypto::Hash256 sr{};
    if (!read_hash256(bytes, off, bh)) {
        return DecodeStatus::TooShort;
    }
    if (!read_hash256(bytes, off, sr)) {
        return DecodeStatus::TooShort;
    }

    out = HistoricalProof{};
    out.kind = static_cast<Kind>(kind);
    out.proof_height = height;
    out.header = hdr;
    out.block_hash = bh;
    out.state_root_at_height = sr;

    if (out.kind == Kind::Account) {
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
        if (off + static_cast<std::size_t>(id_len) > bytes.size()) {
            return DecodeStatus::TooShort;
        }
        out.account_id.assign(reinterpret_cast<const char*>(bytes.data() + off),
                              reinterpret_cast<const char*>(bytes.data() + off + static_cast<std::size_t>(id_len)));
        off += static_cast<std::size_t>(id_len);

        if (off + 16 > bytes.size()) {
            return DecodeStatus::TooShort;
        }
        auto read_u64 = [&](const std::uint8_t* p) -> std::uint64_t {
            std::uint64_t v = 0;
            for (int i = 0; i < 8; ++i) {
                v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
            }
            return v;
        };
        out.account.nonce = read_u64(bytes.data() + off);
        out.account.balance = read_u64(bytes.data() + off + 8);
        off += 16;
    } else if (out.kind == Kind::Tx) {
        std::uint32_t tlen = 0;
        if (!read_u32_le(bytes, off, tlen)) {
            return DecodeStatus::TooShort;
        }
        if (static_cast<std::size_t>(tlen) > opt.legacy_proof_decode.max_tx_bytes) {
            return DecodeStatus::Invalid;
        }
        if (off + static_cast<std::size_t>(tlen) > bytes.size()) {
            return DecodeStatus::TooShort;
        }

        {
            module67::DecodeOptions txopt;
            txopt.max_payload_bytes = opt.legacy_proof_decode.max_tx_bytes;
            Transaction tx;
            const auto st = module67::decode_tx(bytes.subspan(off, tlen), tx, txopt);
            if (st != module67::DecodeStatus::Ok) {
                return DecodeStatus::Invalid;
            }
            out.tx = tx;
            off += static_cast<std::size_t>(tlen);
        }

        std::uint64_t idx = 0;
        {
            const auto st = read_var_u64(bytes, off, idx, vopt);
            if (st != DecodeStatus::Ok) {
                return st;
            }
        }
        out.tx_index = idx;
        out.txid = txid(out.tx);
    } else {
        crypto::Hash256 id{};
        if (!read_hash256(bytes, off, id)) {
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

        std::uint64_t idx = 0;
        {
            const auto st = read_var_u64(bytes, off, idx, vopt);
            if (st != DecodeStatus::Ok) {
                return st;
            }
        }
        out.tx_index = idx;

        out.tx = Transaction{};
        out.tx.payload.clear();
        out.tx.version = 0;
        out.tx.nonce = 0;
        out.tx.fee = 0;
        out.txid = id;
    }

    module81::MerkleMultiProof mp;
    std::size_t mp_consumed = 0;
    {
        const auto st = module81::decode_multiproof(bytes.subspan(off), mp, mp_consumed, opt.multiproof_decode);
        if (st == module81::DecodeStatus::Empty) {
            return DecodeStatus::Empty;
        }
        if (st == module81::DecodeStatus::TooShort) {
            return DecodeStatus::TooShort;
        }
        if (st == module81::DecodeStatus::TooLong) {
            return DecodeStatus::TooLong;
        }
        if (st == module81::DecodeStatus::BadMagic) {
            return DecodeStatus::BadMagic;
        }
        if (st == module81::DecodeStatus::BadVersion) {
            return DecodeStatus::BadVersion;
        }
        if (st == module81::DecodeStatus::NonCanonical) {
            return DecodeStatus::NonCanonical;
        }
        if (st != module81::DecodeStatus::Ok) {
            return DecodeStatus::Invalid;
        }
    }
    out.multiproof = mp;
    off += mp_consumed;

    consumed = off;
    if (consumed != bytes.size()) {
        return DecodeStatus::NonCanonical;
    }

    return DecodeStatus::Ok;
}

std::optional<HistoricalProof> decode_historical_proof(std::span<const std::uint8_t> bytes, const DecodeOptions& opt) {
    HistoricalProof out;
    std::size_t consumed = 0;
    const auto st = decode_historical_proof(bytes, out, consumed, opt);
    if (st != DecodeStatus::Ok || consumed != bytes.size()) {
        return std::nullopt;
    }
    return out;
}

bool verify_historical_proof(const HistoricalProof& p) {
    if (p.header.height != p.proof_height) {
        return false;
    }
    if (block_hash(p.header) != p.block_hash) {
        return false;
    }

    if (p.kind == Kind::Account) {
        if (p.account_id.empty()) {
            return false;
        }
        if (p.multiproof.leaves.size() != 1) {
            return false;
        }
        const auto want_leaf = module80::account_leaf_hash(p.account_id, p.account);
        if (p.multiproof.leaves[0].leaf_hash != want_leaf) {
            return false;
        }
        const auto r = module81::verify_and_root(p.multiproof);
        return r.has_value() && *r == p.state_root_at_height;
    }

    if (p.kind == Kind::Tx) {
        if (p.multiproof.leaves.size() != 1) {
            return false;
        }
        const auto want_leaf = txid(p.tx);
        if (p.multiproof.leaves[0].leaf_hash != want_leaf) {
            return false;
        }
        const auto r = module81::verify_and_root(p.multiproof);
        return r.has_value() && *r == p.header.merkle_root;
    }

    if (p.kind == Kind::Receipt) {
        if (!p.applied) {
            return false;
        }
        if (p.multiproof.leaves.size() != 1) {
            return false;
        }
        if (p.txid == crypto::Hash256{}) {
            return false;
        }
        const auto want_leaf = module80::receipt_leaf_hash(p.txid, p.applied);
        if (p.multiproof.leaves[0].leaf_hash != want_leaf) {
            return false;
        }
        const auto r = module81::verify_and_root(p.multiproof);
        return r.has_value() && *r == p.header.merkle_root;
    }

    return false;
}

std::optional<HistoricalProof> extract_account_proof(const std::filesystem::path& data_dir,
                                                    const std::uint64_t height,
                                                    const std::string_view account_id) {
    if (height == 0) {
        return std::nullopt;
    }

    ChainDB::Options copt;
    copt.storage.schema_version = 1;
    copt.validation.max_tx_payload_bytes = 1024 * 1024;
    copt.validation.max_block_txs = 10000;
    copt.validation.max_tx_version = (std::numeric_limits<std::uint32_t>::max)();

    ChainDB src_db(data_dir / "chain", copt);
    if (!src_db.open()) {
        return std::nullopt;
    }

    const auto tip = src_db.tip();
    if (!tip || tip->height < height) {
        return std::nullopt;
    }

    const auto hdr = src_db.header_by_height(height);
    if (!hdr) {
        return std::nullopt;
    }

    const auto sr = src_db.state_root_by_height(height);
    if (!sr) {
        return std::nullopt;
    }

    const auto gtxt = read_all_text(data_dir / "genesis.json");
    if (!gtxt) {
        return std::nullopt;
    }

    const auto max_supply = parse_json_u64_field(*gtxt, "max_supply");
    const auto alloc = parse_genesis_allocations(*gtxt);
    if (!max_supply || !alloc || alloc->empty()) {
        return std::nullopt;
    }

    const auto st = replay_state_to_height(data_dir, height, *max_supply, *alloc, src_db);
    if (!st) {
        return std::nullopt;
    }

    Storage::Options sopt;
    sopt.schema_version = 1;

    const auto tmp_base = std::filesystem::temp_directory_path() /
                          ("randium_hist_state_" + crypto::to_hex(crypto::sha256(data_dir.string() + ":" + std::to_string(height))));

    Storage stor_state_dir(tmp_base / "state", sopt);
    if (!stor_state_dir.open()) {
        return std::nullopt;
    }

    const auto leaves = build_state_leaves(stor_state_dir, account_id);
    if (!leaves || !leaves->account_leaf_index.has_value() || !leaves->account.has_value()) {
        return std::nullopt;
    }

    const auto root = merkle_root_hashes(leaves->leaves);
    if (!root || *root != *sr) {
        return std::nullopt;
    }

    const std::uint64_t idx = *leaves->account_leaf_index;
    const std::uint64_t targets[1] = {idx};
    const auto mp = module81::build_from_leaves(std::span<const crypto::Hash256>(leaves->leaves.data(), leaves->leaves.size()),
                                                std::span<const std::uint64_t>(targets, 1));
    if (!mp) {
        return std::nullopt;
    }

    HistoricalProof hp;
    hp.kind = Kind::Account;
    hp.proof_height = height;
    hp.header = *hdr;
    hp.block_hash = block_hash(*hdr);
    hp.state_root_at_height = *sr;
    hp.account_id = std::string(account_id);
    hp.account = *leaves->account;
    hp.multiproof = *mp;

    if (!verify_historical_proof(hp)) {
        return std::nullopt;
    }

    return hp;
}

}
