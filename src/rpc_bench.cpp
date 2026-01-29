#include "rand/rpc_bench.hpp"

#include "rand/cli.hpp"
#include "rand/perf.hpp"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <fstream>
#include <initializer_list>
#include <mutex>
#include <random>
#include <span>
#include <sstream>
#include <thread>

namespace randio::module78 {

namespace {

[[nodiscard]] int run_cli(std::initializer_list<std::string> argv, std::ostream& out, std::ostream& err) {
    std::vector<std::string> a;
    a.reserve(argv.size());
    for (const auto& s : argv) {
        a.push_back(s);
    }
    std::vector<std::string_view> v;
    v.reserve(a.size());
    for (const auto& s : a) {
        v.push_back(std::string_view(s));
    }
    return randio::cli::run(std::span<const std::string_view>(v.data(), v.size()), out, err);
}

[[nodiscard]] bool is_hex64(std::string_view s) {
    if (s.size() != 64) {
        return false;
    }
    for (const char c : s) {
        const auto ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string clamp_ascii(std::string s, const std::size_t max_len) {
    if (s.size() > max_len) {
        s.resize(max_len);
    }
    for (char& c : s) {
        if (static_cast<unsigned char>(c) < 32u) {
            c = '_';
        }
    }
    return s;
}

[[nodiscard]] std::string parse_queued_txid_hex32(std::string_view out) {
    const auto pos = out.find("queued=");
    if (pos == std::string_view::npos) {
        return {};
    }
    const auto start = pos + std::string_view("queued=").size();
    auto end = out.find('\n', start);
    if (end == std::string_view::npos) {
        end = out.size();
    }
    const auto v = std::string(out.substr(start, end - start));
    if (!is_hex64(v)) {
        return {};
    }
    return v;
}

[[nodiscard]] std::string parse_contract_hex32(std::string_view out) {
    const auto pos = out.find("contract=");
    if (pos == std::string_view::npos) {
        return {};
    }
    const auto start = pos + std::string_view("contract=").size();
    auto end = out.find('\n', start);
    if (end == std::string_view::npos) {
        end = out.size();
    }
    const auto v = std::string(out.substr(start, end - start));
    if (!is_hex64(v)) {
        return {};
    }
    return v;
}

struct ExecResult final {
    int rc{1};
    std::string out{};
    std::string err{};
};

[[nodiscard]] ExecResult exec_request(const Request& r, const std::filesystem::path& data_dir) {
    std::ostringstream out;
    std::ostringstream err;

    if (r.kind == Request::Kind::RpcGetStatus) {
        const int rc = run_cli({"rpc", "getStatus", data_dir.generic_string()}, out, err);
        return {rc, out.str(), err.str()};
    }
    if (r.kind == Request::Kind::RpcGetSupply) {
        const int rc = run_cli({"rpc", "getSupply", data_dir.generic_string()}, out, err);
        return {rc, out.str(), err.str()};
    }
    if (r.kind == Request::Kind::RpcGetAccount) {
        const int rc = run_cli({"rpc", "getAccount", data_dir.generic_string(), "--id", r.id}, out, err);
        return {rc, out.str(), err.str()};
    }
    if (r.kind == Request::Kind::RpcGetTx) {
        const int rc = run_cli({"rpc", "getTx", data_dir.generic_string(), "--txid", r.txid_hex32}, out, err);
        return {rc, out.str(), err.str()};
    }
    if (r.kind == Request::Kind::RpcGetBlock) {
        const int rc = run_cli({"rpc", "getBlock", data_dir.generic_string(), "--height", std::to_string(r.height)}, out, err);
        return {rc, out.str(), err.str()};
    }
    if (r.kind == Request::Kind::RpcSnapshot) {
        const int rc = run_cli({"rpc", "snapshot", data_dir.generic_string(), "--out", r.out_path.generic_string()}, out, err);
        return {rc, out.str(), err.str()};
    }
    if (r.kind == Request::Kind::ExplorerIndex) {
        const int rc = run_cli({"explorer", "index", data_dir.generic_string(), "--out", r.out_path.generic_string()}, out, err);
        return {rc, out.str(), err.str()};
    }

    err << "unknown request kind\n";
    return {1, out.str(), err.str()};
}

[[nodiscard]] std::string kind_name(const Request::Kind k) {
    switch (k) {
        case Request::Kind::RpcGetStatus:
            return "rpc.getStatus";
        case Request::Kind::RpcGetSupply:
            return "rpc.getSupply";
        case Request::Kind::RpcGetAccount:
            return "rpc.getAccount";
        case Request::Kind::RpcGetTx:
            return "rpc.getTx";
        case Request::Kind::RpcSnapshot:
            return "rpc.snapshot";
        case Request::Kind::ExplorerIndex:
            return "explorer.index";
        case Request::Kind::RpcGetBlock:
            return "rpc.getBlock";
    }
    return "unknown";
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
    return root / "logs" / "rpc_bench_report.json";
}

std::filesystem::path prepare_bench_chain_data_dir(std::filesystem::path base_dir,
                                                  const std::uint64_t seed,
                                                  std::string& out_any_txid_hex32) {
    std::error_code ec;
    std::filesystem::remove_all(base_dir, ec);
    std::filesystem::create_directories(base_dir, ec);

    const auto data_dir = base_dir / "data";

    {
        std::ostringstream o;
        std::ostringstream e;
        (void)run_cli({"init-data-dir", data_dir.generic_string()}, o, e);
    }

    {
        std::ostringstream o;
        std::ostringstream e;
        (void)run_cli({"genesis-init",
                       data_dir.generic_string(),
                       "--max-supply",
                       "1000000",
                       "--alloc",
                       "alice:600000",
                       "--alloc",
                       "bob:400000"},
                      o,
                      e);
    }

    {
        std::ostringstream o;
        std::ostringstream e;
        (void)run_cli({"run-node", data_dir.generic_string(), "--mode", "full", "--ticks", "3"}, o, e);
    }

    {
        std::ostringstream o;
        std::ostringstream e;
        (void)run_cli({"tx",
                       "send-transfer",
                       data_dir.generic_string(),
                       "--from",
                       "alice",
                       "--to",
                       "bob",
                       "--amount",
                       std::to_string((seed % 97u) + 1u),
                       "--fee",
                       "1"},
                      o,
                      e);
        out_any_txid_hex32 = parse_queued_txid_hex32(o.str());
    }

    {
        std::ostringstream o;
        std::ostringstream e;
        (void)run_cli({"run-node", data_dir.generic_string(), "--mode", "full", "--ticks", "2"}, o, e);
    }

    if (out_any_txid_hex32.empty()) {
        out_any_txid_hex32 = std::string(64, '0');
    }

    return data_dir;
}

std::vector<Request> generate_schedule(const GeneratorOptions& opt,
                                      std::string_view known_txid_hex32,
                                      const std::filesystem::path& scratch_dir) {
    std::mt19937_64 rng(opt.seed);
    std::vector<Request> out;
    out.reserve(opt.total_requests);

    const auto mk_out = [&](const std::size_t i, std::string_view name) -> std::filesystem::path {
        std::string fn;
        fn.reserve(64);
        fn += std::string(name);
        fn += "_";
        fn += std::to_string(i);
        fn += ".json";
        fn = clamp_ascii(std::move(fn), opt.max_path_len);
        return scratch_dir / fn;
    };

    for (std::size_t i = 0; i < opt.total_requests; ++i) {
        Request r;
        const auto pick = static_cast<std::uint64_t>(rng() % 100u);
        if (pick < 40u) {
            r.kind = Request::Kind::RpcGetStatus;
        } else if (pick < 70u) {
            r.kind = Request::Kind::RpcGetSupply;
        } else if (pick < 86u) {
            r.kind = Request::Kind::RpcGetAccount;
        } else if (pick < 92u) {
            r.kind = Request::Kind::RpcGetTx;
        } else if (pick < 96u) {
            r.kind = Request::Kind::RpcGetBlock;
        } else if (pick < 98u) {
            r.kind = Request::Kind::RpcSnapshot;
        } else {
            r.kind = Request::Kind::ExplorerIndex;
        }

        if (r.kind == Request::Kind::RpcGetAccount) {
            const auto which = static_cast<int>(rng() % 3u);
            if (which == 0) {
                r.id = "alice";
            } else if (which == 1) {
                r.id = "bob";
            } else {
                r.id = "missing_user_" + std::to_string(static_cast<std::uint64_t>(rng() % 10000u));
            }
            r.id = clamp_ascii(std::move(r.id), opt.max_id_len);
        }

        if (r.kind == Request::Kind::RpcGetTx) {
            r.txid_hex32 = std::string(known_txid_hex32);
            if (!is_hex64(r.txid_hex32)) {
                r.txid_hex32 = std::string(64, '0');
            }
        }

        if (r.kind == Request::Kind::RpcGetBlock) {
            const auto h = static_cast<std::uint64_t>(rng() % (static_cast<std::uint64_t>(opt.page_size) + 1u));
            r.height = h;
        }

        if (r.kind == Request::Kind::RpcSnapshot) {
            r.out_path = mk_out(i, "snapshot");
        }

        if (r.kind == Request::Kind::ExplorerIndex) {
            r.out_path = mk_out(i, "explorer_index");
        }

        out.push_back(std::move(r));
    }

    return out;
}

ScenarioResult run_scenario(const ScenarioOptions& opt,
                            const std::filesystem::path& data_dir,
                            std::string_view known_txid_hex32,
                            const std::filesystem::path& scratch_dir) {
    ScenarioResult r;
    r.name = opt.name;

    std::error_code ec;
    std::filesystem::create_directories(scratch_dir, ec);

    const auto schedule = generate_schedule(opt.gen, known_txid_hex32, scratch_dir);
    r.requests = schedule.size();

    randio::perf::reset();

    const std::size_t conc = std::max<std::size_t>(1, opt.concurrency);
    std::vector<std::thread> threads;
    threads.reserve(conc);

    std::atomic<std::size_t> ok{0};
    std::atomic<std::size_t> failed{0};

    for (std::size_t t = 0; t < conc; ++t) {
        threads.emplace_back([&, t]() {
            for (std::size_t i = t; i < schedule.size(); i += conc) {
                const auto& req = schedule[i];
                const auto ex = exec_request(req, data_dir);

                if (ex.rc == 0) {
                    ok.fetch_add(1, std::memory_order_relaxed);
                } else {
                    failed.fetch_add(1, std::memory_order_relaxed);
                }

                randio::perf::add(static_cast<std::uint64_t>(ex.out.size() + ex.err.size()));
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    r.ok = ok.load(std::memory_order_relaxed);
    r.failed = failed.load(std::memory_order_relaxed);
    r.perf_cost = randio::perf::value();
    return r;
}

SuiteReport run_default_suite() {
    return run_suite(std::filesystem::temp_directory_path() / "randium_rpc_bench", 77);
}

SuiteReport run_suite(std::filesystem::path scratch_base, const std::uint64_t seed) {
    SuiteReport rep;
    rep.seed = seed;
    rep.report_path = default_report_path();

    std::string any_txid;
    rep.data_dir = prepare_bench_chain_data_dir(scratch_base / "chain", rep.seed, any_txid);

    const auto scratch = scratch_base / "scratch";
    std::error_code ec;
    std::filesystem::remove_all(scratch, ec);
    std::filesystem::create_directories(scratch, ec);

    {
        ScenarioOptions opt;
        opt.name = "light_status_supply";
        opt.concurrency = 1;
        opt.gen.seed = rep.seed ^ 0x1111u;
        opt.gen.total_requests = 400;
        opt.gen.page_size = 8;
        rep.scenarios.push_back(run_scenario(opt, rep.data_dir, any_txid, scratch / "s1"));
    }

    {
        ScenarioOptions opt;
        opt.name = "mixed_account_tx";
        opt.concurrency = 4;
        opt.gen.seed = rep.seed ^ 0x2222u;
        opt.gen.total_requests = 300;
        opt.gen.page_size = 16;
        rep.scenarios.push_back(run_scenario(opt, rep.data_dir, any_txid, scratch / "s2"));
    }

    {
        ScenarioOptions opt;
        opt.name = "snapshot_and_explorer";
        opt.concurrency = 1;
        opt.gen.seed = rep.seed ^ 0x3333u;
        opt.gen.total_requests = 40;
        opt.gen.page_size = 4;
        rep.scenarios.push_back(run_scenario(opt, rep.data_dir, any_txid, scratch / "s3"));
    }

    return rep;
}

bool write_report_json(const SuiteReport& rep) {
    std::error_code ec;
    std::filesystem::create_directories(rep.report_path.parent_path(), ec);

    std::string j;
    j += "{\n";
    j += "  \"seed\": " + std::to_string(rep.seed) + ",\n";
    j += "  \"data_dir\": \"" + rep.data_dir.generic_string() + "\",\n";
    j += "  \"scenarios\": [\n";
    for (std::size_t i = 0; i < rep.scenarios.size(); ++i) {
        const auto& s = rep.scenarios[i];
        j += "    {\n";
        j += "      \"name\": \"" + s.name + "\",\n";
        j += "      \"requests\": " + std::to_string(s.requests) + ",\n";
        j += "      \"ok\": " + std::to_string(s.ok) + ",\n";
        j += "      \"failed\": " + std::to_string(s.failed) + ",\n";
        j += "      \"perf_cost\": " + std::to_string(s.perf_cost) + "\n";
        j += "    }";
        j += (i + 1 == rep.scenarios.size()) ? "\n" : ",\n";
    }
    j += "  ]\n";
    j += "}\n";

    std::ofstream f(rep.report_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        return false;
    }
    f.write(j.data(), static_cast<std::streamsize>(j.size()));
    f.flush();
    return f.good();
}

}
