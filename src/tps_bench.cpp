#include "rand/tps_bench.hpp"

#include "rand/exec_engine.hpp"
#include "rand/mempool.hpp"
#include "rand/tx_codec.hpp"
#include "rand/vm.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <optional>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <string_view>

namespace randio::module102 {

namespace {

[[nodiscard]] std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (const char c : s) {
        if (c == '\\') {
            out += "\\\\";
        } else if (c == '"') {
            out += "\\\"";
        } else if (static_cast<unsigned char>(c) < 32u) {
            out += "_";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> u64_le(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> u32_le(const std::uint32_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(4);
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
    return out;
}

[[nodiscard]] Transaction make_transfer_tx_v2(const std::string& from,
                                             const std::string& to,
                                             const std::uint64_t amount,
                                             const std::uint64_t expected_nonce,
                                             const std::uint64_t max_fee_per_gas,
                                             const std::uint64_t priority_fee_per_gas) {
    Transaction tx;
    tx.version = 2;
    tx.nonce = expected_nonce;
    tx.fee = max_fee_per_gas;
    tx.max_fee_per_gas = max_fee_per_gas;
    tx.priority_fee_per_gas = priority_fee_per_gas;
    tx.compute_limit = 1;
    tx.compute_price_per_unit = 1;

    std::vector<std::uint8_t> p;
    p.reserve(1 + 1 + from.size() + 1 + to.size() + 8 + 8);
    p.push_back(static_cast<std::uint8_t>(0x01));
    p.push_back(static_cast<std::uint8_t>(from.size()));
    p.insert(p.end(), from.begin(), from.end());
    p.push_back(static_cast<std::uint8_t>(to.size()));
    p.insert(p.end(), to.begin(), to.end());
    const auto ab = u64_le(amount);
    const auto nb = u64_le(expected_nonce);
    p.insert(p.end(), ab.begin(), ab.end());
    p.insert(p.end(), nb.begin(), nb.end());

    tx.payload = std::move(p);
    return tx;
}

[[nodiscard]] Transaction make_deploy_tx_v2(const std::string& deployer,
                                           const std::uint64_t nonce,
                                           const std::uint64_t gas_limit,
                                           const std::vector<std::uint8_t>& code,
                                           const std::uint64_t max_fee_per_gas,
                                           const std::uint64_t priority_fee_per_gas) {
    Transaction tx;
    tx.version = 2;
    tx.nonce = nonce;
    tx.fee = max_fee_per_gas;
    tx.max_fee_per_gas = max_fee_per_gas;
    tx.priority_fee_per_gas = priority_fee_per_gas;
    tx.compute_limit = gas_limit;
    tx.compute_price_per_unit = 1;

    std::vector<std::uint8_t> p;
    p.reserve(1 + 1 + deployer.size() + 8 + 4 + code.size());
    p.push_back(static_cast<std::uint8_t>(0x02));
    p.push_back(static_cast<std::uint8_t>(deployer.size()));
    p.insert(p.end(), deployer.begin(), deployer.end());

    const auto gb = u64_le(gas_limit);
    p.insert(p.end(), gb.begin(), gb.end());

    const auto clen = u32_le(static_cast<std::uint32_t>(code.size()));
    p.insert(p.end(), clen.begin(), clen.end());
    p.insert(p.end(), code.begin(), code.end());

    tx.payload = std::move(p);
    return tx;
}

[[nodiscard]] Transaction make_call_tx_v2(const std::string& caller,
                                         const std::uint64_t nonce,
                                         const crypto::Hash256& contract,
                                         const std::uint64_t gas_limit,
                                         const std::vector<std::uint8_t>& input,
                                         const std::uint64_t max_fee_per_gas,
                                         const std::uint64_t priority_fee_per_gas) {
    Transaction tx;
    tx.version = 2;
    tx.nonce = nonce;
    tx.fee = max_fee_per_gas;
    tx.max_fee_per_gas = max_fee_per_gas;
    tx.priority_fee_per_gas = priority_fee_per_gas;
    tx.compute_limit = gas_limit;
    tx.compute_price_per_unit = 1;

    std::vector<std::uint8_t> p;
    p.reserve(1 + 1 + caller.size() + 32 + 8 + 4 + input.size());
    p.push_back(static_cast<std::uint8_t>(0x03));
    p.push_back(static_cast<std::uint8_t>(caller.size()));
    p.insert(p.end(), caller.begin(), caller.end());

    p.insert(p.end(), contract.begin(), contract.end());

    const auto gb = u64_le(gas_limit);
    p.insert(p.end(), gb.begin(), gb.end());

    const auto ilen = u32_le(static_cast<std::uint32_t>(input.size()));
    p.insert(p.end(), ilen.begin(), ilen.end());
    p.insert(p.end(), input.begin(), input.end());

    tx.payload = std::move(p);
    return tx;
}

[[nodiscard]] std::vector<std::uint8_t> rand20_marker_code() {
    vm::Bytecode bc;
    bc.version = 1;
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    const auto m = crypto::sha256("RAND20");
    bc.code.insert(bc.code.end(), m.begin(), m.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));
    return vm::VM::encode_bytecode(bc);
}

[[nodiscard]] std::vector<std::uint8_t> randnft_marker_code() {
    vm::Bytecode bc;
    bc.version = 1;
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    const auto m = crypto::sha256("RANDNFT");
    bc.code.insert(bc.code.end(), m.begin(), m.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));
    return vm::VM::encode_bytecode(bc);
}

[[nodiscard]] crypto::Hash256 contract_addr_for_deploy_tx(const Transaction& deploy_tx) {
    const auto id = txid(deploy_tx);
    return crypto::sha256(std::span<const std::uint8_t>(id.data(), id.size()));
}

[[nodiscard]] std::string contract_hex_for_deploy_tx(const Transaction& deploy_tx) {
    return crypto::to_hex(contract_addr_for_deploy_tx(deploy_tx));
}

[[nodiscard]] std::optional<std::uint64_t> read_storage_u64(GlobalState& st, const std::string& contract_hex, const crypto::Hash256& key) {
    const auto v = st.get_contract_storage(contract_hex, key);
    if (!v) {
        return 0;
    }
    if (v->size() != 8) {
        return std::nullopt;
    }
    std::uint64_t out = 0;
    for (int i = 0; i < 8; ++i) {
        out |= (static_cast<std::uint64_t>((*v)[static_cast<std::size_t>(i)]) << (8u * i));
    }
    return out;
}

[[nodiscard]] crypto::Hash256 rand20_supply_key() { return crypto::sha256("rand20:supply"); }
[[nodiscard]] crypto::Hash256 rand20_evt_seq_key() { return crypto::sha256("rand20:evt_seq"); }
[[nodiscard]] crypto::Hash256 rand20_evt_key(const std::uint64_t seq) { return crypto::sha256("rand20:evt:" + std::to_string(seq)); }

[[nodiscard]] crypto::Hash256 randnft_supply_key() { return crypto::sha256("randnft:supply"); }
[[nodiscard]] crypto::Hash256 randnft_evt_seq_key() { return crypto::sha256("randnft:evt_seq"); }
[[nodiscard]] crypto::Hash256 randnft_evt_key(const std::uint64_t seq) { return crypto::sha256("randnft:evt:" + std::to_string(seq)); }
[[nodiscard]] crypto::Hash256 randnft_token_id(const crypto::Hash256& contract, const std::uint64_t supply_next) {
    const auto c = crypto::to_hex(contract);
    return crypto::sha256("randnft:token:" + c + ":" + std::to_string(supply_next));
}

template <typename KeyFn>
[[nodiscard]] crypto::Hash256 events_hash(GlobalState& st,
                                         const std::string& contract_hex,
                                         const crypto::Hash256& evt_seq_key,
                                         KeyFn evt_key_fn) {
    const auto seq_opt = read_storage_u64(st, contract_hex, evt_seq_key);
    const std::uint64_t seq = seq_opt.value_or(0);

    std::vector<std::uint8_t> acc;
    for (std::uint64_t i = 1; i <= seq; ++i) {
        const auto k = evt_key_fn(i);
        const auto v = st.get_contract_storage(contract_hex, k);
        if (!v) {
            continue;
        }
        acc.insert(acc.end(), v->begin(), v->end());
    }

    return crypto::sha256(std::span<const std::uint8_t>(acc.data(), acc.size()));
}

struct TickTotals final {
    std::uint64_t blocks{0};
    std::uint64_t applied{0};
    std::uint64_t aborted{0};
    std::uint64_t gas_used{0};
};

[[nodiscard]] std::uint64_t bench_priority_fee_for_nonce(const std::uint64_t nonce) {
    const std::uint64_t base = 1024;
    return (nonce < base) ? (base - nonce) : 1;
}

[[nodiscard]] TickTotals run_ticks(GlobalState& st,
                                  Mempool& mp,
                                  const std::size_t max_batch_txs,
                                  const std::size_t max_batch_bytes,
                                  const std::uint64_t max_account_compute,
                                  const std::uint64_t max_ticks) {
    TickTotals tot;

    TransactionScheduler::Options so;
    so.max_batch_txs = max_batch_txs;
    so.max_batch_bytes = max_batch_bytes;
    so.max_account_compute_per_batch = max_account_compute;
    TransactionScheduler sched(so);

    DeterministicExecutor ex(DeterministicExecutor::Options{1});

    for (std::uint64_t tick = 0; tick < max_ticks && mp.size() > 0; ++tick) {
        const auto batch = sched.build_batch(mp);
        const auto plan = ExecutionPlanner::plan(batch);
        const auto res = ex.execute(st, plan, tick);

        std::uint64_t gas = 0;
        std::uint64_t applied = 0;
        std::uint64_t aborted = 0;

        for (const auto& tr : res.tx_results) {
            if (tr.status == ExecutionResult::TxStatus::Applied) {
                gas += tr.gas_used;
                applied += 1;
            } else if (tr.status == ExecutionResult::TxStatus::Aborted) {
                aborted += 1;
            }
        }

        tot.blocks += 1;
        tot.applied += applied;
        tot.aborted += aborted;
        tot.gas_used += gas;

        for (const auto& id : res.applied) {
            (void)mp.remove(id);
        }
        for (const auto& id : res.aborted) {
            (void)mp.remove(id);
        }
        for (const auto& id : res.rejected) {
            (void)mp.remove(id);
        }
    }

    return tot;
}

[[nodiscard]] std::filesystem::path bench_base_dir(std::string_view name) {
    const auto root = find_repo_root();
    return root / "logs" / "tps_bench_tmp" / std::string(name);
}

[[nodiscard]] bool clean_dir(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
    if (ec) {
        return false;
    }
    std::filesystem::create_directories(p, ec);
    return !ec;
}

[[nodiscard]] void init_simple_genesis(GlobalState& st, const std::vector<std::string>& ids, const std::uint64_t balance_each) {
    std::vector<std::pair<std::string, std::uint64_t>> alloc;
    alloc.reserve(ids.size());
    std::uint64_t supply = 0;
    for (const auto& id : ids) {
        alloc.emplace_back(id, balance_each);
        supply += balance_each;
    }
    StateDelta delta;
    const bool ok_g = st.init_genesis_supply(supply, alloc, delta);
    assert(ok_g);

    StateDelta vd;
    const bool ok_v = st.set_protocol_version(2, vd);
    assert(ok_v);
}

[[nodiscard]] WorkloadReport run_transfer_only(const SuiteOptions& opt) {
    WorkloadReport rep;
    rep.name = "transfer_only";
    rep.seed = opt.seed ^ 0x1111u;

    const std::size_t accounts = opt.ci_mode ? 64 : 256;
    const std::size_t txs = opt.ci_mode ? 2000 : 20000;

    const auto dir = bench_base_dir(rep.name) / std::to_string(opt.run_id);
    const bool ok_dir = clean_dir(dir);
    assert(ok_dir);

    GlobalState::Options gs;
    gs.storage.schema_version = 1;
    GlobalState st(dir / "state", gs);
    const bool ok_open = st.open();
    assert(ok_open);

    std::vector<std::string> ids;
    ids.reserve(accounts);
    for (std::size_t i = 0; i < accounts; ++i) {
        ids.push_back("acc" + std::to_string(i));
    }
    init_simple_genesis(st, ids, 1000000);

    rep.base_fee_start = st.base_fee_per_gas();
    const auto tip0 = st.tip_pool_total().value_or(0);

    Mempool::Options mp_opt;
    mp_opt.max_txs = txs + 100;
    mp_opt.max_total_bytes = 128ULL * 1024ULL * 1024ULL;
    mp_opt.min_fee_rate_per_byte = 0;
    mp_opt.max_tx_payload_bytes = 4096;
    mp_opt.max_tx_version = 4;
    mp_opt.base_fee_per_gas = rep.base_fee_start;
    mp_opt.shards = 4;
    Mempool mp(mp_opt);

    std::vector<std::uint64_t> nonces(accounts, 0);
    for (std::size_t i = 0; i < txs; ++i) {
        const auto from_i = i % accounts;
        const auto to_i = (i * 7 + 3) % accounts;
        const auto amt = 1 + (i % 5);

        const auto from = ids[from_i];
        const auto to = ids[to_i];

        const auto nonce = nonces[from_i];
        nonces[from_i] += 1;

        const std::uint64_t prio = bench_priority_fee_for_nonce(nonce);
        const std::uint64_t max_fee = rep.base_fee_start + 2048;

        const auto tx = make_transfer_tx_v2(from, to, amt, nonce, max_fee, prio);
        (void)mp.add(tx);
    }

    const auto t0 = std::chrono::steady_clock::now();
    const std::uint64_t max_ticks = (opt.blocks != 0) ? opt.blocks : 2000;
    const auto tot = run_ticks(st, mp, 4000, 32ULL * 1024ULL * 1024ULL, 32, max_ticks);
    const auto t1 = std::chrono::steady_clock::now();

    rep.elapsed_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
    rep.applied_tx = tot.applied;
    rep.aborted_tx = tot.aborted;
    rep.gas_used_total = tot.gas_used;
    rep.blocks_produced = tot.blocks;

    rep.base_fee_end = st.base_fee_per_gas();
    const auto tip1 = st.tip_pool_total().value_or(0);
    rep.tip_pool_collected = (tip1 >= tip0) ? (tip1 - tip0) : 0;

    rep.state_root_final = st.state_root();

    const double elapsed_s = (rep.elapsed_ms == 0) ? 0.0 : (static_cast<double>(rep.elapsed_ms) / 1000.0);
    rep.tps = (elapsed_s == 0.0) ? 0.0 : (static_cast<double>(rep.applied_tx) / elapsed_s);

    return rep;
}

[[nodiscard]] WorkloadReport run_rand20_heavy(const SuiteOptions& opt) {
    WorkloadReport rep;
    rep.name = "rand20_heavy";
    rep.seed = opt.seed ^ 0x2222u;

    const std::size_t accounts = opt.ci_mode ? 64 : 256;
    const std::size_t transfers = opt.ci_mode ? 1500 : 15000;

    const auto dir = bench_base_dir(rep.name) / std::to_string(opt.run_id);
    const bool ok_dir = clean_dir(dir);
    assert(ok_dir);

    GlobalState::Options gs;
    gs.storage.schema_version = 1;
    GlobalState st(dir / "state", gs);
    const bool ok_open = st.open();
    assert(ok_open);

    std::vector<std::pair<std::string, std::uint64_t>> alloc;
    alloc.reserve(accounts + 1);
    std::uint64_t supply = 0;

    alloc.emplace_back("admin", 100000000);
    supply += 100000000;

    std::vector<std::string> ids;
    ids.reserve(accounts);
    for (std::size_t i = 0; i < accounts; ++i) {
        ids.push_back("acc" + std::to_string(i));
        alloc.emplace_back(ids.back(), 1000000);
        supply += 1000000;
    }

    StateDelta gd;
    const bool ok_g = st.init_genesis_supply(supply, alloc, gd);
    assert(ok_g);

    StateDelta vd;
    const bool ok_v = st.set_protocol_version(2, vd);
    assert(ok_v);

    rep.base_fee_start = st.base_fee_per_gas();
    const auto tip0 = st.tip_pool_total().value_or(0);

    Mempool::Options mp_opt;
    mp_opt.max_txs = transfers + accounts + 100;
    mp_opt.max_total_bytes = 128ULL * 1024ULL * 1024ULL;
    mp_opt.min_fee_rate_per_byte = 0;
    mp_opt.max_tx_payload_bytes = 64 * 1024;
    mp_opt.max_tx_version = 4;
    mp_opt.base_fee_per_gas = rep.base_fee_start;
    mp_opt.shards = 4;
    Mempool mp(mp_opt);

    std::vector<std::uint64_t> nonces(accounts, 0);
    std::uint64_t admin_nonce = 0;

    const std::uint64_t max_fee = rep.base_fee_start + 1000000;

    const auto code = rand20_marker_code();
    const auto deploy_tx = make_deploy_tx_v2("admin", admin_nonce, 50000, code, max_fee, 5);
    admin_nonce += 1;
    const auto contract_hex = contract_hex_for_deploy_tx(deploy_tx);
    const auto contract_addr = contract_addr_for_deploy_tx(deploy_tx);
    const bool ok_add = mp.add(deploy_tx);
    assert(ok_add);

    {
        const auto tot_deploy = run_ticks(st, mp, 16, 32ULL * 1024ULL * 1024ULL, 100000, 50);
        assert(tot_deploy.applied == 1);
        assert(mp.size() == 0);
    }

    const std::uint64_t init_amt = 1000;
    for (std::size_t i = 0; i < accounts; ++i) {
        const auto to_addr = crypto::sha256(std::string_view(ids[i]));
        std::vector<std::uint8_t> input;
        input.reserve(1 + 32 + 8);
        input.push_back(0x02);
        input.insert(input.end(), to_addr.begin(), to_addr.end());
        const auto ab = u64_le(init_amt);
        input.insert(input.end(), ab.begin(), ab.end());
        const auto tx = make_call_tx_v2("admin", admin_nonce, contract_addr, 50000, input, max_fee, bench_priority_fee_for_nonce(admin_nonce));
        admin_nonce += 1;
        (void)mp.add(tx);
    }

    for (std::size_t i = 0; i < transfers; ++i) {
        const auto from_i = i % accounts;
        const auto to_i = (i * 7 + 3) % accounts;
        const auto amt = 1 + (i % 5);

        const auto to_addr = crypto::sha256(std::string_view(ids[to_i]));
        std::vector<std::uint8_t> input;
        input.reserve(1 + 32 + 8);
        input.push_back(0x01);
        input.insert(input.end(), to_addr.begin(), to_addr.end());
        const auto ab = u64_le(amt);
        input.insert(input.end(), ab.begin(), ab.end());

        const auto nonce = nonces[from_i];
        nonces[from_i] += 1;

        const auto tx = make_call_tx_v2(ids[from_i], nonce, contract_addr, 50000, input, max_fee, bench_priority_fee_for_nonce(nonce));
        (void)mp.add(tx);
    }

    const auto t0 = std::chrono::steady_clock::now();
    const std::uint64_t max_ticks = (opt.blocks != 0) ? opt.blocks : 3000;
    const auto tot = run_ticks(st, mp, 2000, 32ULL * 1024ULL * 1024ULL, 100000, max_ticks);
    const auto t1 = std::chrono::steady_clock::now();

    rep.elapsed_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
    rep.applied_tx = tot.applied;
    rep.aborted_tx = tot.aborted;
    rep.gas_used_total = tot.gas_used;
    rep.blocks_produced = tot.blocks;

    rep.base_fee_end = st.base_fee_per_gas();
    const auto tip1 = st.tip_pool_total().value_or(0);
    rep.tip_pool_collected = (tip1 >= tip0) ? (tip1 - tip0) : 0;

    rep.state_root_final = st.state_root();

    const auto expected_supply = static_cast<std::uint64_t>(accounts) * init_amt;
    rep.rand20_supply = read_storage_u64(st, contract_hex, rand20_supply_key()).value_or(0);
    rep.rand20_events_hash = events_hash(st, contract_hex, rand20_evt_seq_key(), [](const std::uint64_t i) { return rand20_evt_key(i); });
    assert(rep.rand20_supply == expected_supply);

    const double elapsed_s = (rep.elapsed_ms == 0) ? 0.0 : (static_cast<double>(rep.elapsed_ms) / 1000.0);
    rep.tps = (elapsed_s == 0.0) ? 0.0 : (static_cast<double>(rep.applied_tx) / elapsed_s);

    return rep;
}

[[nodiscard]] WorkloadReport run_mixed_contract_calls(const SuiteOptions& opt) {
    WorkloadReport rep;
    rep.name = "mixed_contract_calls";
    rep.seed = opt.seed ^ 0x3333u;

    const std::size_t accounts = opt.ci_mode ? 48 : 192;
    const std::size_t calls = opt.ci_mode ? 1200 : 12000;

    const auto dir = bench_base_dir(rep.name) / std::to_string(opt.run_id);
    const bool ok_dir = clean_dir(dir);
    assert(ok_dir);

    GlobalState::Options gs;
    gs.storage.schema_version = 1;
    GlobalState st(dir / "state", gs);
    const bool ok_open = st.open();
    assert(ok_open);

    std::vector<std::pair<std::string, std::uint64_t>> alloc;
    alloc.reserve(accounts + 1);
    std::uint64_t supply = 0;

    alloc.emplace_back("admin", 200000000);
    supply += 200000000;

    std::vector<std::string> ids;
    ids.reserve(accounts);
    for (std::size_t i = 0; i < accounts; ++i) {
        ids.push_back("acc" + std::to_string(i));
        alloc.emplace_back(ids.back(), 2000000);
        supply += 2000000;
    }

    StateDelta gd;
    const bool ok_g = st.init_genesis_supply(supply, alloc, gd);
    assert(ok_g);

    StateDelta vd;
    const bool ok_v = st.set_protocol_version(2, vd);
    assert(ok_v);

    rep.base_fee_start = st.base_fee_per_gas();
    const auto tip0 = st.tip_pool_total().value_or(0);

    Mempool::Options mp_opt;
    mp_opt.max_txs = calls + accounts * 2 + 200;
    mp_opt.max_total_bytes = 256ULL * 1024ULL * 1024ULL;
    mp_opt.min_fee_rate_per_byte = 0;
    mp_opt.max_tx_payload_bytes = 64 * 1024;
    mp_opt.max_tx_version = 4;
    mp_opt.base_fee_per_gas = rep.base_fee_start;
    mp_opt.shards = 4;
    Mempool mp(mp_opt);

    std::vector<std::uint64_t> nonces(accounts, 0);
    std::uint64_t admin_nonce = 0;

    const std::uint64_t max_fee = rep.base_fee_start + 1000000;

    const auto rand20_code = rand20_marker_code();
    const auto d20 = make_deploy_tx_v2("admin", admin_nonce, 50000, rand20_code, max_fee, 5);
    admin_nonce += 1;
    const auto rand20_hex = contract_hex_for_deploy_tx(d20);
    const auto rand20_addr = contract_addr_for_deploy_tx(d20);
    const bool ok_add20 = mp.add(d20);
    assert(ok_add20);

    const auto randnft_code = randnft_marker_code();
    const auto dn = make_deploy_tx_v2("admin", admin_nonce, 50000, randnft_code, max_fee, 5);
    admin_nonce += 1;
    const auto randnft_hex = contract_hex_for_deploy_tx(dn);
    const auto randnft_addr = contract_addr_for_deploy_tx(dn);
    const bool ok_addn = mp.add(dn);
    assert(ok_addn);

    {
        const auto tot_deploy = run_ticks(st, mp, 16, 32ULL * 1024ULL * 1024ULL, 100000, 50);
        assert(tot_deploy.applied == 2);
        assert(mp.size() == 0);
    }

    const std::uint64_t init_amt = 1000;
    for (std::size_t i = 0; i < accounts; ++i) {
        const auto to_addr = crypto::sha256(std::string_view(ids[i]));
        std::vector<std::uint8_t> input;
        input.reserve(1 + 32 + 8);
        input.push_back(0x02);
        input.insert(input.end(), to_addr.begin(), to_addr.end());
        const auto ab = u64_le(init_amt);
        input.insert(input.end(), ab.begin(), ab.end());
        const auto tx = make_call_tx_v2("admin", admin_nonce, rand20_addr, 50000, input, max_fee, bench_priority_fee_for_nonce(admin_nonce));
        admin_nonce += 1;
        (void)mp.add(tx);
    }

    std::mt19937_64 rng(rep.seed);

    struct NftOwned final {
        crypto::Hash256 tid{};
        std::size_t owner_idx{0};
    };
    std::vector<NftOwned> nft_owned;
    nft_owned.reserve(calls / 4);
    std::uint64_t nft_minted = 0;

    for (std::size_t i = 0; i < calls; ++i) {
        const auto op = static_cast<std::uint64_t>(rng() % 5);
        const auto ai = static_cast<std::size_t>(rng() % accounts);
        const auto bi = static_cast<std::size_t>(rng() % accounts);

        if (op == 0) {
            const auto from_i = ai;
            const auto to_i = bi;
            const auto amt = 1 + (i % 5);
            const auto to_addr = crypto::sha256(std::string_view(ids[to_i]));

            std::vector<std::uint8_t> input;
            input.reserve(1 + 32 + 8);
            input.push_back(0x01);
            input.insert(input.end(), to_addr.begin(), to_addr.end());
            const auto ab = u64_le(amt);
            input.insert(input.end(), ab.begin(), ab.end());

            const auto nonce = nonces[from_i];
            nonces[from_i] += 1;

            (void)mp.add(make_call_tx_v2(ids[from_i], nonce, rand20_addr, 50000, input, max_fee, bench_priority_fee_for_nonce(nonce)));
        } else if (op == 1) {
            const auto to_addr = crypto::sha256(std::string_view(ids[bi]));
            const std::string meta = "m" + std::to_string(i);

            std::vector<std::uint8_t> input;
            input.reserve(1 + 32 + 4 + meta.size());
            input.push_back(0x01);
            input.insert(input.end(), to_addr.begin(), to_addr.end());
            const auto ml = u32_le(static_cast<std::uint32_t>(meta.size()));
            input.insert(input.end(), ml.begin(), ml.end());
            input.insert(input.end(), meta.begin(), meta.end());

            (void)mp.add(make_call_tx_v2("admin", admin_nonce, randnft_addr, 50000, input, max_fee, bench_priority_fee_for_nonce(admin_nonce)));
            admin_nonce += 1;

            nft_minted += 1;
            const auto tid = randnft_token_id(randnft_addr, nft_minted);
            nft_owned.push_back(NftOwned{tid, bi});
        } else if (op == 2) {
            if (!nft_owned.empty()) {
                const auto idx = static_cast<std::size_t>(rng() % nft_owned.size());
                const auto tid = nft_owned[idx].tid;
                const auto owner_idx = nft_owned[idx].owner_idx;
                const auto to_addr = crypto::sha256(std::string_view(ids[bi]));

                std::vector<std::uint8_t> input;
                input.reserve(1 + 32 + 32);
                input.push_back(0x02);
                input.insert(input.end(), tid.begin(), tid.end());
                input.insert(input.end(), to_addr.begin(), to_addr.end());

                const auto nonce = nonces[owner_idx];
                nonces[owner_idx] += 1;

                (void)mp.add(make_call_tx_v2(ids[owner_idx], nonce, randnft_addr, 50000, input, max_fee, bench_priority_fee_for_nonce(nonce)));
                nft_owned[idx].owner_idx = bi;
            }
        } else if (op == 3) {
            if (!nft_owned.empty()) {
                const auto tid = nft_owned.back().tid;
                nft_owned.pop_back();

                std::vector<std::uint8_t> input;
                input.reserve(1 + 32);
                input.push_back(0x03);
                input.insert(input.end(), tid.begin(), tid.end());

                (void)mp.add(make_call_tx_v2("admin", admin_nonce, randnft_addr, 50000, input, max_fee, bench_priority_fee_for_nonce(admin_nonce)));
                admin_nonce += 1;
            }
        } else {
            const auto from_i = ai;
            const auto to_i = bi;
            const auto amt = 1;

            const auto tx = make_transfer_tx_v2(ids[from_i], ids[to_i], amt, nonces[from_i], max_fee, bench_priority_fee_for_nonce(nonces[from_i]));
            nonces[from_i] += 1;
            (void)mp.add(tx);
        }
    }

    const auto t0 = std::chrono::steady_clock::now();
    const std::uint64_t max_ticks = (opt.blocks != 0) ? opt.blocks : 4000;
    const auto tot = run_ticks(st, mp, 2000, 32ULL * 1024ULL * 1024ULL, 1024, max_ticks);
    const auto t1 = std::chrono::steady_clock::now();

    rep.elapsed_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
    rep.applied_tx = tot.applied;
    rep.aborted_tx = tot.aborted;
    rep.gas_used_total = tot.gas_used;
    rep.blocks_produced = tot.blocks;

    rep.base_fee_end = st.base_fee_per_gas();
    const auto tip1 = st.tip_pool_total().value_or(0);
    rep.tip_pool_collected = (tip1 >= tip0) ? (tip1 - tip0) : 0;

    rep.state_root_final = st.state_root();

    rep.rand20_supply = read_storage_u64(st, rand20_hex, rand20_supply_key()).value_or(0);
    rep.rand20_events_hash = events_hash(st, rand20_hex, rand20_evt_seq_key(), [](const std::uint64_t i) { return rand20_evt_key(i); });

    rep.randnft_supply = read_storage_u64(st, randnft_hex, randnft_supply_key()).value_or(0);
    rep.randnft_events_hash = events_hash(st, randnft_hex, randnft_evt_seq_key(), [](const std::uint64_t i) { return randnft_evt_key(i); });

    const double elapsed_s = (rep.elapsed_ms == 0) ? 0.0 : (static_cast<double>(rep.elapsed_ms) / 1000.0);
    rep.tps = (elapsed_s == 0.0) ? 0.0 : (static_cast<double>(rep.applied_tx) / elapsed_s);

    return rep;
}

[[nodiscard]] WorkloadReport run_mempool_ingest_stress(const SuiteOptions& opt) {
    WorkloadReport rep;
    rep.name = "mempool_ingest_stress";
    rep.seed = opt.seed ^ 0x4444u;

    const std::size_t txs = opt.ci_mode ? 6000 : 60000;

    const auto dir = bench_base_dir(rep.name) / std::to_string(opt.run_id);
    const bool ok_dir = clean_dir(dir);
    assert(ok_dir);

    GlobalState::Options gs;
    gs.storage.schema_version = 1;
    GlobalState st(dir / "state", gs);
    const bool ok_open = st.open();
    assert(ok_open);

    std::vector<std::string> ids;
    ids.reserve(512);
    for (std::size_t i = 0; i < 512; ++i) {
        ids.push_back("acc" + std::to_string(i));
    }
    ids.push_back("sink");
    init_simple_genesis(st, ids, 1000000);

    rep.base_fee_start = st.base_fee_per_gas();
    const auto tip0 = st.tip_pool_total().value_or(0);

    Mempool::Options mp_opt;
    mp_opt.max_txs = txs / 2;
    mp_opt.max_total_bytes = 8ULL * 1024ULL * 1024ULL;
    mp_opt.min_fee_rate_per_byte = 0;
    mp_opt.max_tx_payload_bytes = 4096;
    mp_opt.max_tx_version = 4;
    mp_opt.base_fee_per_gas = rep.base_fee_start;
    mp_opt.shards = 4;
    Mempool mp(mp_opt);

    std::vector<std::vector<std::uint8_t>> blobs;
    blobs.reserve(txs);
    for (std::size_t i = 0; i < txs; ++i) {
        const auto from_i = i % ids.size();
        const auto nonce = static_cast<std::uint64_t>(i / ids.size());
        const auto max_fee = rep.base_fee_start + 2048;
        const auto prio = bench_priority_fee_for_nonce(nonce);
        const auto tx = make_transfer_tx_v2(ids[from_i], "sink", 1, nonce, max_fee, prio);
        blobs.push_back(module67::encode_tx(tx));
    }

    module67::DecodeOptions dop;
    dop.max_payload_bytes = 4096;

    std::mt19937_64 rng(rep.seed);
    std::vector<std::size_t> order(blobs.size());
    for (std::size_t i = 0; i < order.size(); ++i) {
        order[i] = i;
    }
    std::shuffle(order.begin(), order.end(), rng);

    const auto t0 = std::chrono::steady_clock::now();
    for (const auto idx : order) {
        const auto tx_opt = module67::decode_tx(std::span<const std::uint8_t>(blobs[idx].data(), blobs[idx].size()), dop);
        if (tx_opt) {
            (void)mp.add(*tx_opt);
        }
    }

    TransactionScheduler::Options so;
    so.max_batch_txs = 128;
    so.max_batch_bytes = 4 * 1024 * 1024;
    so.max_account_compute_per_batch = 1024;
    TransactionScheduler sched(so);
    const auto batch = sched.build_batch(mp);

    rep.mempool_batch_txids.clear();
    for (const auto& stx : batch.txs) {
        rep.mempool_batch_txids.push_back(stx.id);
        if (rep.mempool_batch_txids.size() >= 64) {
            break;
        }
    }

    const std::uint64_t max_ticks = (opt.blocks != 0) ? opt.blocks : 2000;
    const auto tot = run_ticks(st, mp, 4000, 32ULL * 1024ULL * 1024ULL, 1024, max_ticks);
    const auto t1 = std::chrono::steady_clock::now();

    rep.elapsed_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
    rep.applied_tx = tot.applied;
    rep.aborted_tx = tot.aborted;
    rep.gas_used_total = tot.gas_used;
    rep.blocks_produced = tot.blocks;

    rep.base_fee_end = st.base_fee_per_gas();
    const auto tip1 = st.tip_pool_total().value_or(0);
    rep.tip_pool_collected = (tip1 >= tip0) ? (tip1 - tip0) : 0;

    rep.state_root_final = st.state_root();

    const double elapsed_s = (rep.elapsed_ms == 0) ? 0.0 : (static_cast<double>(rep.elapsed_ms) / 1000.0);
    rep.tps = (elapsed_s == 0.0) ? 0.0 : (static_cast<double>(rep.applied_tx) / elapsed_s);

    return rep;
}

[[nodiscard]] std::string workload_to_json(const WorkloadReport& w, const bool include_time_fields);

[[nodiscard]] std::string canonical_json_for_signature(const SuiteReport& rep) {
    std::ostringstream out;
    out << "{";
    out << "\"seed\":" << rep.seed;
    out << ",\"workloads\":[";
    for (std::size_t i = 0; i < rep.workloads.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << workload_to_json(rep.workloads[i], false);
    }
    out << "]";
    out << "}";
    return out.str();
}

[[nodiscard]] crypto::Hash256 determinism_signature_for(const SuiteReport& rep) {
    const auto canon = canonical_json_for_signature(rep);
    return crypto::sha256(std::string_view(canon));
}

[[nodiscard]] void append_hash_hex_json(std::ostringstream& out, const crypto::Hash256& h) {
    out << '"' << crypto::to_hex(h) << '"';
}

[[nodiscard]] std::string workload_to_json(const WorkloadReport& w, const bool include_time_fields) {
    std::ostringstream out;
    out << "{";
    out << "\"name\":\"" << json_escape(w.name) << "\"";
    out << ",\"seed\":" << w.seed;
    if (include_time_fields) {
        out << ",\"elapsed_ms\":" << w.elapsed_ms;
        out << ",\"tps\":" << w.tps;
    }
    out << ",\"applied_tx\":" << w.applied_tx;
    out << ",\"aborted_tx\":" << w.aborted_tx;
    out << ",\"gas_used_total\":" << w.gas_used_total;
    out << ",\"base_fee_start\":" << w.base_fee_start;
    out << ",\"base_fee_end\":" << w.base_fee_end;
    out << ",\"tip_pool_collected\":" << w.tip_pool_collected;
    out << ",\"blocks_produced\":" << w.blocks_produced;
    out << ",\"state_root_final\":";
    append_hash_hex_json(out, w.state_root_final);
    out << ",\"rand20_supply\":" << w.rand20_supply;
    out << ",\"rand20_events_hash\":";
    append_hash_hex_json(out, w.rand20_events_hash);
    out << ",\"randnft_supply\":" << w.randnft_supply;
    out << ",\"randnft_events_hash\":";
    append_hash_hex_json(out, w.randnft_events_hash);
    out << ",\"mempool_batch_txids\":[";
    for (std::size_t i = 0; i < w.mempool_batch_txids.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        append_hash_hex_json(out, w.mempool_batch_txids[i]);
    }
    out << "]";
    out << "}";
    return out.str();
}

} // namespace

std::filesystem::path find_repo_root() {
    auto p = std::filesystem::current_path();
    for (int i = 0; i < 10; ++i) {
        if (std::filesystem::exists(p / "CMakeLists.txt")) {
            return p;
        }
        if (!p.has_parent_path()) {
            break;
        }
        p = p.parent_path();
    }
    return std::filesystem::current_path();
}

std::filesystem::path default_report_path() {
    const auto root = find_repo_root();
    return root / "logs" / "tps_bench_report.json";
}

SuiteReport run_suite(const SuiteOptions& opt) {
    static std::uint64_t suite_run_id = 0;
    SuiteOptions local = opt;
    local.run_id = suite_run_id;
    suite_run_id += 1;

    SuiteReport rep;
    rep.seed = local.seed;
    rep.report_path = default_report_path();

    rep.workloads.clear();
    if (local.workload.empty() || local.workload == "transfer_only") {
        rep.workloads.push_back(run_transfer_only(local));
    }
    if (local.workload.empty() || local.workload == "rand20_heavy") {
        rep.workloads.push_back(run_rand20_heavy(local));
    }
    if (local.workload.empty() || local.workload == "mixed_contract_calls") {
        rep.workloads.push_back(run_mixed_contract_calls(local));
    }
    if (local.workload.empty() || local.workload == "mempool_ingest_stress") {
        rep.workloads.push_back(run_mempool_ingest_stress(local));
    }

    rep.determinism_signature = determinism_signature_for(rep);
    return rep;
}

SuiteReport run_default_suite() {
    SuiteOptions opt;
    opt.seed = 77;
    opt.ci_mode = true;
    return run_suite(opt);
}

std::string to_json(const SuiteReport& rep) {
    std::ostringstream out;
    out << "{";
    out << "\"seed\":" << rep.seed;
    out << ",\"report_path\":\"" << json_escape(rep.report_path.generic_string()) << "\"";
    out << ",\"determinism_signature\":";
    append_hash_hex_json(out, rep.determinism_signature);
    out << ",\"workloads\":[";
    for (std::size_t i = 0; i < rep.workloads.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << workload_to_json(rep.workloads[i], true);
    }
    out << "]";
    out << "}";
    return out.str();
}

std::string to_json_without_time_fields(const SuiteReport& rep) {
    std::ostringstream out;
    out << "{";
    out << "\"seed\":" << rep.seed;
    out << ",\"determinism_signature\":";
    append_hash_hex_json(out, rep.determinism_signature);
    out << ",\"workloads\":[";
    for (std::size_t i = 0; i < rep.workloads.size(); ++i) {
        if (i != 0) {
            out << ",";
        }
        out << workload_to_json(rep.workloads[i], false);
    }
    out << "]";
    out << "}";
    return out.str();
}

bool write_report_json(const SuiteReport& rep) {
    std::error_code ec;
    std::filesystem::create_directories(rep.report_path.parent_path(), ec);

    std::ofstream f(rep.report_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        return false;
    }
    const auto s = to_json(rep);
    f.write(s.data(), static_cast<std::streamsize>(s.size()));
    f.flush();
    return f.good();
}

} // namespace randio::module102
