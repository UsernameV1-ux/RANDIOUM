#include "rand/module118/fuzz.hpp"

#include "rand/exec_engine.hpp"
#include "rand/hex.hpp"
#include "rand/module118/contract.hpp"
#include "rand/oracle.hpp"
#include "rand/sha256.hpp"
#include "rand/validator.hpp"

#include <algorithm>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace randio::module118 {
namespace {

[[nodiscard]] std::uint64_t rotl64_(const std::uint64_t x, const unsigned r) {
    return (x << (r & 63u)) | (x >> ((64u - r) & 63u));
}

[[nodiscard]] std::uint64_t mix_u64_(std::uint64_t h, const std::uint64_t x) {
    h ^= x + 0x9e3779b97f4a7c15ULL + (h << 6u) + (h >> 2u);
    h = rotl64_(h, 17u);
    return h;
}

[[nodiscard]] std::uint64_t read_u64_le_(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[static_cast<std::size_t>(i)]) << (8u * i));
    }
    return v;
}

[[nodiscard]] std::uint32_t read_u32_le_(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) | (static_cast<std::uint32_t>(p[2]) << 16u) |
           (static_cast<std::uint32_t>(p[3]) << 24u);
}

[[nodiscard]] std::uint64_t bounded_u64_(const std::uint64_t x, const std::uint64_t lo, const std::uint64_t hi) {
    if (hi <= lo) {
        return lo;
    }
    return lo + (x % (hi - lo + 1));
}

[[nodiscard]] std::vector<std::uint8_t> encode_u64_(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> encode_register_params_(const randio::crypto::Hash256& feed_id) {
    std::vector<std::uint8_t> in;
    in.reserve(1 + 7 * 8 + 32);
    in.push_back(0x10);

    auto append_u64 = [&](const std::uint64_t v) {
        const auto b = encode_u64_(v);
        in.insert(in.end(), b.begin(), b.end());
    };

    append_u64(15000);
    append_u64(12000);
    append_u64(2000);
    append_u64(1000000);
    append_u64(1);
    append_u64(1);
    append_u64(100);

    in.insert(in.end(), feed_id.begin(), feed_id.end());
    return in;
}

[[nodiscard]] std::vector<std::uint8_t> oracle117_signed_bytes_(const randio::module117::OracleReport& r) {
    std::vector<std::uint8_t> out;
    out.reserve(7 + 32 + 8 + 8 + 8 + 4 + 32);
    out.insert(out.end(), {'O', 'R', 'A', 'C', 'L', 'E', '1'});
    out.insert(out.end(), r.feed.id.begin(), r.feed.id.end());
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((r.height >> (8u * i)) & 0xFFu));
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((r.tick >> (8u * i)) & 0xFFu));
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((r.value_u64 >> (8u * i)) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>(r.decimals & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((r.decimals >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((r.decimals >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((r.decimals >> 24u) & 0xFFu));
    out.insert(out.end(), r.reporter.id.begin(), r.reporter.id.end());
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> make_module118_input_(std::uint8_t op, std::uint64_t v);
[[nodiscard]] std::vector<std::uint8_t> make_module118_liq_input_(std::string_view target, std::uint64_t burn_amt);

[[nodiscard]] bool is_ascii_text_(std::span<const std::uint8_t> b) {
    for (const auto c : b) {
        if (c == '\n' || c == '\r' || c == '\t') {
            continue;
        }
        if (c < 0x20 || c > 0x7Eu) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::optional<std::vector<std::vector<std::uint8_t>>> parse_payloads_ascii_hex_(std::span<const std::uint8_t> b,
                                                                                              const std::size_t max_ops,
                                                                                              const std::size_t max_input_bytes) {
    std::vector<std::vector<std::uint8_t>> out;
    out.reserve(max_ops);

    std::string line;
    line.reserve(1024);
    auto flush_line = [&]() {
        if (out.size() >= max_ops) {
            line.clear();
            return;
        }
        auto s = line;
        line.clear();
        s.erase(std::remove_if(s.begin(), s.end(), [](const unsigned char ch) { return ch == ' ' || ch == '\t'; }), s.end());
        if (s.empty()) {
            return;
        }
        const auto dec = randio::module66::from_hex(s, max_input_bytes);
        if (!dec) {
            return;
        }
        out.push_back(*dec);
    };

    for (const auto c : b) {
        if (c == '\n' || c == '\r') {
            flush_line();
            continue;
        }
        if (line.size() < 4096) {
            line.push_back(static_cast<char>(c));
        }
    }
    flush_line();
    return out;
}

[[nodiscard]] std::optional<std::vector<std::vector<std::uint8_t>>> parse_payloads_framed_(std::span<const std::uint8_t> b,
                                                                                           const std::size_t max_ops,
                                                                                           const std::size_t max_input_bytes) {
    std::vector<std::vector<std::uint8_t>> out;
    out.reserve(max_ops);

    std::size_t off = 0;
    while (out.size() < max_ops) {
        if (off + 2 > b.size()) {
            break;
        }
        const auto len = static_cast<std::size_t>(b[off]) | (static_cast<std::size_t>(b[off + 1]) << 8u);
        off += 2;
        if (len == 0 || len > max_input_bytes) {
            break;
        }
        if (off + len > b.size()) {
            break;
        }
        std::vector<std::uint8_t> payload;
        payload.insert(payload.end(), b.begin() + static_cast<std::ptrdiff_t>(off), b.begin() + static_cast<std::ptrdiff_t>(off + len));
        off += len;
        out.push_back(std::move(payload));
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> canonicalize_payload_(const std::vector<std::uint8_t>& in, const randio::crypto::Hash256& oracle_feed_id) {
    if (in.empty()) {
        return {};
    }
    const auto op = in[0];
    if (op == 0x10) {
        if (in.size() != 1 + 7 * 8 + 32) {
            return in;
        }
        bool all_zero = true;
        for (std::size_t i = 1 + 7 * 8; i < in.size(); ++i) {
            all_zero = all_zero && (in[i] == 0);
        }
        if (!all_zero) {
            return in;
        }
        auto out = in;
        std::copy(oracle_feed_id.begin(), oracle_feed_id.end(), out.begin() + static_cast<std::ptrdiff_t>(1 + 7 * 8));
        return out;
    }
    if (op >= 0x11 && op <= 0x14) {
        if (in.size() != 1 + 8) {
            return in;
        }
        const auto amt = read_u64_le_(in.data() + 1);
        return make_module118_input_(op, amt);
    }
    if (op == 0x15) {
        if (in.size() < 1 + 1 + 8) {
            return in;
        }
        const auto n = static_cast<std::size_t>(in[1]);
        if (1 + 1 + n + 8 != in.size()) {
            return in;
        }
        const std::string target(reinterpret_cast<const char*>(in.data() + 2), reinterpret_cast<const char*>(in.data() + 2 + n));
        const auto burn = read_u64_le_(in.data() + 2 + n);
        return make_module118_liq_input_(target, burn);
    }
    return in;
}

[[nodiscard]] randio::Transaction make_deploy_tx_(const std::string& deployer,
                                                 const std::uint64_t nonce,
                                                 const std::uint64_t fee,
                                                 const std::uint64_t gas_limit,
                                                 const std::vector<std::uint8_t>& code_bytes) {
    randio::Transaction tx;
    tx.nonce = nonce;
    tx.fee = fee;

    std::vector<std::uint8_t> p;
    p.push_back(0x02);
    p.push_back(static_cast<std::uint8_t>(deployer.size()));
    p.insert(p.end(), deployer.begin(), deployer.end());
    for (int i = 0; i < 8; ++i) {
        p.push_back(static_cast<std::uint8_t>((gas_limit >> (8u * i)) & 0xFFu));
    }
    const std::uint32_t clen = static_cast<std::uint32_t>(code_bytes.size());
    p.push_back(static_cast<std::uint8_t>(clen & 0xFFu));
    p.push_back(static_cast<std::uint8_t>((clen >> 8u) & 0xFFu));
    p.push_back(static_cast<std::uint8_t>((clen >> 16u) & 0xFFu));
    p.push_back(static_cast<std::uint8_t>((clen >> 24u) & 0xFFu));
    p.insert(p.end(), code_bytes.begin(), code_bytes.end());
    tx.payload = std::move(p);
    return tx;
}

[[nodiscard]] randio::Transaction make_call_tx_(const std::string& caller,
                                               const std::uint64_t nonce,
                                               const std::uint64_t fee,
                                               const randio::crypto::Hash256& contract,
                                               const std::uint64_t gas_limit,
                                               const std::vector<std::uint8_t>& input) {
    randio::Transaction tx;
    tx.nonce = nonce;
    tx.fee = fee;

    std::vector<std::uint8_t> p;
    p.push_back(0x03);
    p.push_back(static_cast<std::uint8_t>(caller.size()));
    p.insert(p.end(), caller.begin(), caller.end());
    p.insert(p.end(), contract.begin(), contract.end());
    for (int i = 0; i < 8; ++i) {
        p.push_back(static_cast<std::uint8_t>((gas_limit >> (8u * i)) & 0xFFu));
    }
    const std::uint32_t ilen = static_cast<std::uint32_t>(input.size());
    p.push_back(static_cast<std::uint8_t>(ilen & 0xFFu));
    p.push_back(static_cast<std::uint8_t>((ilen >> 8u) & 0xFFu));
    p.push_back(static_cast<std::uint8_t>((ilen >> 16u) & 0xFFu));
    p.push_back(static_cast<std::uint8_t>((ilen >> 24u) & 0xFFu));
    p.insert(p.end(), input.begin(), input.end());
    tx.payload = std::move(p);
    return tx;
}

[[nodiscard]] std::vector<std::uint8_t> make_module118_input_(const std::uint8_t op, const std::uint64_t v) {
    std::vector<std::uint8_t> in;
    in.reserve(1 + 8);
    in.push_back(op);
    const auto b = encode_u64_(v);
    in.insert(in.end(), b.begin(), b.end());
    return in;
}

[[nodiscard]] std::vector<std::uint8_t> make_module118_liq_input_(const std::string_view target, const std::uint64_t burn_amt) {
    std::vector<std::uint8_t> in;
    in.reserve(1 + 1 + target.size() + 8);
    in.push_back(0x15);
    const auto n = static_cast<std::size_t>(std::min<std::size_t>(255, target.size()));
    in.push_back(static_cast<std::uint8_t>(n));
    in.insert(in.end(), target.begin(), target.begin() + static_cast<std::ptrdiff_t>(n));
    const auto b = encode_u64_(burn_amt);
    in.insert(in.end(), b.begin(), b.end());
    return in;
}

[[nodiscard]] std::uint64_t fold_state_(randio::GlobalState& st, const randio::crypto::Hash256& contract, const std::vector<std::string>& ids) {
    std::uint64_t h = 0;
    const auto root = st.state_root();
    h = mix_u64_(h, read_u64_le_(root.data()));

    const auto chex = randio::crypto::to_hex(contract);
    auto read_u64_le_opt = [&](const std::optional<std::vector<std::uint8_t>>& v) -> std::uint64_t {
        if (!v || v->size() != 8) {
            return 0;
        }
        return read_u64_le_(v->data());
    };

    h = mix_u64_(h, read_u64_le_opt(st.get_contract_storage(chex, randio::crypto::sha256("stable118:evt_seq"))));
    h = mix_u64_(h, read_u64_le_opt(st.get_contract_storage(chex, randio::crypto::sha256("stable118:total_collateral"))));
    h = mix_u64_(h, read_u64_le_opt(st.get_contract_storage(chex, randio::crypto::sha256("stable118:total_debt"))));

    for (const auto& id : ids) {
        h = mix_u64_(h, read_u64_le_opt(st.get_contract_storage(chex, randio::crypto::sha256("stable118:bal:" + id))));
        h = mix_u64_(h, read_u64_le_opt(st.get_contract_storage(chex, randio::crypto::sha256("stable118:collateral:" + id))));
        h = mix_u64_(h, read_u64_le_opt(st.get_contract_storage(chex, randio::crypto::sha256("stable118:debt:" + id))));
    }

    return h;
}

} // namespace

FuzzResult stable118_fuzz(std::span<const std::uint8_t> data, const FuzzOptions& opt) {
    FuzzResult out;

    const auto base = std::filesystem::temp_directory_path() / "randium_fuzz_stable118";
    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    std::filesystem::create_directories(base, ec);
    if (ec) {
        out.signature = 1;
        return out;
    }

    randio::GlobalState::Options gs_opt;
    gs_opt.storage.schema_version = 1;
    randio::GlobalState st(base / "state", gs_opt);
    if (!st.open()) {
        out.signature = 2;
        return out;
    }

    randio::StateDelta gd;
    (void)st.init_genesis_supply(1000000, {{"owner", 500000}, {"alice", 250000}, {"bob", 250000}}, gd);

    randio::module117::FeedConfig fc;
    fc.name = "BTC/USD";
    fc.id = randio::module117::feed_id_from_name(fc.name);
    fc.decimals = 0;
    fc.max_history_points = 8;
    fc.min_quorum_weight = 1;
    fc.max_deviation_bps = 10000;
    fc.enabled = true;
    randio::StateDelta fd;
    (void)randio::module117::feed_register(st, fc, fd);

    const auto rep_sec = randio::crypto::sha256("oracle117:stable118:fuzz:sec");
    const auto kp = randio::ValidatorKeypair::from_secret(rep_sec);
    randio::module117::ReporterConfig rc;
    rc.id.id = randio::crypto::sha256("oracle117:stable118:fuzz:rep");
    rc.pubkey = kp.pubkey;
    rc.weight = 1;
    randio::StateDelta rd;
    (void)randio::module117::reporter_register(st, rc, rd);

    {
        randio::module117::OracleReport r;
        r.feed = fc.id;
        r.height = 10;
        r.tick = 1;
        r.value_u64 = 2;
        r.decimals = fc.decimals;
        r.reporter = rc.id;
        const auto msg = oracle117_signed_bytes_(r);
        r.signature = kp.sign(std::span<const std::uint8_t>(msg.data(), msg.size()));
        randio::StateDelta d1;
        (void)randio::module117::apply_report(st, r, d1);
        randio::StateDelta d2;
        (void)randio::module117::finalize_price(st, fc.id, r.height, r.tick, d2);
    }

    randio::TransactionScheduler sched(randio::TransactionScheduler::Options{128, 256 * 1024});
    randio::DeterministicExecutor ex(randio::DeterministicExecutor::Options{1});

    const auto marker_code = randio::module118::stable118_marker_code();
    const auto deploy = make_deploy_tx_("owner", 0, 1, 50000, marker_code);
    const auto did = randio::txid(deploy);
    const auto contract = randio::crypto::sha256(std::span<const std::uint8_t>(did.data(), did.size()));

    auto exec_block = [&](const std::uint64_t h, const std::vector<randio::Transaction>& txs) {
        randio::Mempool mp(randio::Mempool::Options{});
        for (const auto& tx : txs) {
            (void)mp.add(tx);
        }
        const auto batch = sched.build_batch(mp);
        const auto plan = randio::ExecutionPlanner::plan(batch);
        return ex.execute(st, plan, h);
    };

    {
        const auto res = exec_block(1, {deploy});
        out.signature = mix_u64_(out.signature, static_cast<std::uint64_t>(res.applied.size()));
    }

    const auto contract_hex = randio::crypto::to_hex(contract);

    const auto max_n = static_cast<std::size_t>(std::min<std::size_t>(opt.max_input_bytes, data.size()));
    const auto b = std::span<const std::uint8_t>(data.data(), max_n);

    const std::vector<std::string> users = {"owner", "alice", "bob"};

    const std::uint64_t base_h = 11;

    std::uint64_t nonce_owner = st.get_account("owner").value_or(randio::Account{}).nonce;
    std::uint64_t nonce_alice = st.get_account("alice").value_or(randio::Account{}).nonce;
    std::uint64_t nonce_bob = st.get_account("bob").value_or(randio::Account{}).nonce;

    auto next_nonce = [&](const std::string& who) -> std::uint64_t {
        if (who == "owner") {
            return nonce_owner++;
        }
        if (who == "alice") {
            return nonce_alice++;
        }
        return nonce_bob++;
    };

    auto make_tx = [&](const std::string& who, const std::vector<std::uint8_t>& in) {
        return make_call_tx_(who, next_nonce(who), 1, contract, 50000, in);
    };

    {
        const auto in = encode_register_params_(fc.id.id);
        const auto tx = make_tx("owner", in);
        const auto r = exec_block(10, {tx});
        out.signature = mix_u64_(out.signature, static_cast<std::uint64_t>(r.applied.size()));
        out.signature = mix_u64_(out.signature, fold_state_(st, contract, users));
    }

    const std::size_t max_ops = std::max<std::size_t>(1, opt.max_ops);
    const auto payloads = is_ascii_text_(b) ? parse_payloads_ascii_hex_(b, max_ops, opt.max_input_bytes) : parse_payloads_framed_(b, max_ops, opt.max_input_bytes);
    if (payloads) {
        for (std::size_t i = 0; i < payloads->size() && i < max_ops; ++i) {
            const auto& raw = (*payloads)[i];
            if (raw.empty()) {
                continue;
            }

            const auto canon = canonicalize_payload_(raw, fc.id.id);
            if (!canon.empty()) {
                out.signature = mix_u64_(out.signature, static_cast<std::uint64_t>(canon.size()));
                if (canon.size() >= 8) {
                    out.signature = mix_u64_(out.signature, read_u64_le_(canon.data()));
                }
            }

            const auto& who = users[i % users.size()];
            const auto before_root = st.state_root();
            const auto tx = make_tx(who, canon.empty() ? raw : canon);
            const auto h = base_h + static_cast<std::uint64_t>(i);
            const auto r = exec_block(h, {tx});
            out.signature = mix_u64_(out.signature, static_cast<std::uint64_t>(r.applied.size()));

            if (r.applied.empty()) {
                if (st.state_root() != before_root) {
                    out.signature ^= 0xBAD0BAD0BAD0BAD0ULL;
                }
            }

            out.signature = mix_u64_(out.signature, fold_state_(st, contract, users));
        }
    }

    return out;
}

}
