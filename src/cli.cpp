#include "rand/cli.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include "rand/econ_sim.hpp"
#include "rand/sha256.hpp"
#include "rand/state.hpp"
#include "rand/tx.hpp"
#include "rand/validator.hpp"

#include "rand/chain_db.hpp"
#include "rand/exec_engine.hpp"
#include "rand/mempool.hpp"
#include "rand/vm.hpp"

#include "rand/config.hpp"
#include "rand/obs.hpp"
#include "rand/hash256_codec.hpp"
#include "rand/u64_codec.hpp"
#include "rand/proof.hpp"
#include "rand/historical_proof.hpp"
#include "rand/light_client.hpp"
#include "rand/consensus/checkpoint.hpp"

#include "rand/perf.hpp"
#include "rand/rpc_bench.hpp"
#include "rand/tps_bench.hpp"

#include "rand/audit/trace.hpp"
#include "rand/audit/trace_from_exec.hpp"
#include "rand/tx_codec.hpp"
#include "rand/evm_logs.hpp"
#include "rand/eth/jsonrpc_shim.hpp"

#include "rand/bridge/light_verify.hpp"

#include "rand/wrap/apply.hpp"
#include "rand/wrap/contract.hpp"

#include "rand/oracle.hpp"

#include "rand/module118/contract.hpp"
 
 #include "rand/module119/amm/contract.hpp"
 #include "rand/module119/lend/contract.hpp"

#if MOONRAND_ENABLE_MODULE108
#include "rand/module108.hpp"
#endif

namespace randio::cli {

int run(const std::span<const std::string_view> args, std::ostream& out, std::ostream& err);

namespace {

[[nodiscard]] bool parse_u64(std::string_view s, std::uint64_t& out);
[[nodiscard]] bool write_all(const std::filesystem::path& p, std::string_view s);
[[nodiscard]] std::optional<std::string> read_all(const std::filesystem::path& p);
[[nodiscard]] std::string json_escape(std::string_view s);
[[nodiscard]] std::optional<std::string> json_get_string(std::string_view s, std::string_view key);

[[nodiscard]] std::optional<std::vector<std::uint8_t>> bytes_from_hex(std::string_view hex);
[[nodiscard]] std::string bytes_to_hex(std::span<const std::uint8_t> b);
[[nodiscard]] std::optional<crypto::Hash256> hash256_from_hex(std::string_view hex);

[[nodiscard]] Transaction make_transfer_tx(const std::string& from,
                                          const std::string& to,
                                          std::uint64_t amount,
                                          std::uint64_t expected_nonce,
                                          std::uint64_t fee,
                                          std::uint32_t protocol_version);

[[nodiscard]] Transaction make_deploy_tx(const std::string& deployer,
                                        std::uint64_t expected_nonce,
                                        std::uint64_t fee,
                                        std::uint64_t gas_limit,
                                        std::span<const std::uint8_t> code,
                                        std::uint32_t protocol_version);

[[nodiscard]] Transaction make_call_tx(const std::string& caller,
                                      std::uint64_t expected_nonce,
                                      std::uint64_t fee,
                                      const crypto::Hash256& contract,
                                      std::uint64_t gas_limit,
                                      std::span<const std::uint8_t> input,
                                      std::uint32_t protocol_version);

struct NetworkPreset final {
    std::string chain_id;
    std::uint32_t chain_magic{0};
    std::uint32_t p2p_port{0};
    std::uint32_t rpc_port{0};
};
[[nodiscard]] std::optional<NetworkPreset> preset_for(std::string_view name);

[[nodiscard]] std::optional<std::uint64_t> parse_json_u64_field(std::string_view s, std::string_view key);
[[nodiscard]] std::optional<std::vector<std::pair<std::string, std::uint64_t>>> parse_genesis_allocations(std::string_view s);

void print_usage(std::ostream& out);

[[nodiscard]] std::string make_genesis_json(std::string_view chain_id,
                                           std::uint32_t chain_magic,
                                           std::uint32_t p2p_port,
                                           std::uint32_t rpc_port,
                                           std::uint64_t max_supply,
                                           const std::vector<std::pair<std::string, std::uint64_t>>& alloc);

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

[[nodiscard]] std::string oracle_err_name(randio::module117::OracleError e) {
    using randio::module117::OracleError;
    if (e == OracleError::OK) return "OK";
    if (e == OracleError::FEED_NOT_FOUND) return "FeedNotFound";
    if (e == OracleError::INVALID_DECIMALS) return "InvalidDecimals";
    if (e == OracleError::INVALID_VALUE) return "InvalidValue";
    if (e == OracleError::INVALID_SIGNATURE) return "InvalidSignature";
    if (e == OracleError::UNAUTHORIZED_REPORTER) return "UnauthorizedReporter";
    if (e == OracleError::DUPLICATE_REPORT) return "DuplicateReport";
    if (e == OracleError::INSUFFICIENT_QUORUM) return "InsufficientQuorum";
    if (e == OracleError::REPLAYED_REPORT) return "ReplayedReport";
    if (e == OracleError::OVERFLOW) return "Overflow";
    return "InvariantFail";
}

[[nodiscard]] int cmd_oracle(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 4) {
        print_usage(err);
        return 1;
    }

    const auto sub = std::string(args[1]);
    const auto data_dir = std::filesystem::path(args[2]);
    std::filesystem::path out_path;

    auto emit = [&](std::string_view j, const int rc) -> int {
        if (!out_path.empty()) {
            if (!write_all(out_path, j)) {
                err << "write failed\n";
                return 1;
            }
            out << "ok\n";
            return rc;
        }
        out << j;
        return rc;
    };

    auto parse_bool = [](std::string_view s, bool& v) -> bool {
        if (s == "true" || s == "1") {
            v = true;
            return true;
        }
        if (s == "false" || s == "0") {
            v = false;
            return true;
        }
        return false;
    };

    if (sub == "feed-register") {
        std::string name;
        std::uint64_t max_history = 0;
        std::uint64_t min_quorum = 0;
        std::uint64_t max_dev_bps = 0;
        std::uint64_t decimals_u64 = 0;
        bool enabled = true;
        bool has_name = false;
        bool has_dec = false;
        bool has_h = false;
        bool has_q = false;
        bool has_m = false;

        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--name" && i + 1 < args.size()) {
                name = std::string(args[i + 1]);
                has_name = true;
                i += 1;
                continue;
            }
            if (args[i] == "--decimals" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], decimals_u64)) {
                    err << "bad --decimals\n";
                    return 1;
                }
                has_dec = true;
                i += 1;
                continue;
            }
            if (args[i] == "--max-history" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], max_history)) {
                    err << "bad --max-history\n";
                    return 1;
                }
                has_h = true;
                i += 1;
                continue;
            }
            if (args[i] == "--min-quorum" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], min_quorum)) {
                    err << "bad --min-quorum\n";
                    return 1;
                }
                has_q = true;
                i += 1;
                continue;
            }
            if (args[i] == "--max-deviation-bps" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], max_dev_bps)) {
                    err << "bad --max-deviation-bps\n";
                    return 1;
                }
                has_m = true;
                i += 1;
                continue;
            }
            if (args[i] == "--enabled" && i + 1 < args.size()) {
                if (!parse_bool(args[i + 1], enabled)) {
                    err << "bad --enabled\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }

        if (!has_name || !has_dec || !has_h || !has_q || !has_m) {
            err << "missing params\n";
            return 1;
        }

        randio::GlobalState::Options opt;
        opt.storage.schema_version = 1;
        randio::GlobalState st(data_dir, opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }

        randio::module117::FeedConfig fc;
        fc.name = name;
        fc.id = randio::module117::feed_id_from_name(fc.name);
        fc.decimals = static_cast<std::uint32_t>(decimals_u64);
        fc.max_history_points = max_history;
        fc.min_quorum_weight = min_quorum;
        fc.max_deviation_bps = max_dev_bps;
        fc.enabled = enabled;

        randio::StateDelta d;
        const bool ok = randio::module117::feed_register(st, fc, d);
        std::string j;
        j += "{\n";
        j += "  \"ok\": " + std::string(ok ? "true" : "false") + ",\n";
        j += "  \"err\": \"" + std::string(ok ? "OK" : "BadConfig") + "\",\n";
        j += "  \"feed_id\": \"" + crypto::to_hex(fc.id.id) + "\"\n";
        j += "}\n";
        return emit(j, ok ? 0 : 1);
    }

    if (sub == "reporter-register") {
        crypto::Hash256 rid{};
        crypto::Hash256 pub{};
        std::uint64_t w = 0;
        bool has_id = false;
        bool has_pub = false;
        bool has_w = false;

        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--id" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --id\n";
                    return 1;
                }
                rid = *h;
                has_id = true;
                i += 1;
                continue;
            }
            if (args[i] == "--pubkey" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --pubkey\n";
                    return 1;
                }
                pub = *h;
                has_pub = true;
                i += 1;
                continue;
            }
            if (args[i] == "--weight" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], w)) {
                    err << "bad --weight\n";
                    return 1;
                }
                has_w = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }

        if (!has_id || !has_pub || !has_w) {
            err << "missing params\n";
            return 1;
        }

        randio::GlobalState::Options opt;
        opt.storage.schema_version = 1;
        randio::GlobalState st(data_dir, opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }

        randio::module117::ReporterConfig rc;
        rc.id.id = rid;
        rc.pubkey = pub;
        rc.weight = w;

        randio::StateDelta d;
        const bool ok = randio::module117::reporter_register(st, rc, d);

        std::string j;
        j += "{\n";
        j += "  \"ok\": " + std::string(ok ? "true" : "false") + ",\n";
        j += "  \"err\": \"" + std::string(ok ? "OK" : "BadConfig") + "\",\n";
        j += "  \"reporter_id\": \"" + crypto::to_hex(rid) + "\"\n";
        j += "}\n";
        return emit(j, ok ? 0 : 1);
    }

    if (sub == "report") {
        std::string feed_name;
        crypto::Hash256 reporter{};
        crypto::Hash256 sig{};
        std::uint64_t height = 0;
        std::uint64_t tick = 0;
        std::uint64_t value = 0;
        std::uint64_t decimals_u64 = 0;
        bool has_f = false;
        bool has_r = false;
        bool has_h = false;
        bool has_t = false;
        bool has_v = false;
        bool has_d = false;
        bool has_s = false;

        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--feed-name" && i + 1 < args.size()) {
                feed_name = std::string(args[i + 1]);
                has_f = true;
                i += 1;
                continue;
            }
            if (args[i] == "--reporter" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --reporter\n";
                    return 1;
                }
                reporter = *h;
                has_r = true;
                i += 1;
                continue;
            }
            if (args[i] == "--height" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], height)) {
                    err << "bad --height\n";
                    return 1;
                }
                has_h = true;
                i += 1;
                continue;
            }
            if (args[i] == "--tick" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], tick)) {
                    err << "bad --tick\n";
                    return 1;
                }
                has_t = true;
                i += 1;
                continue;
            }
            if (args[i] == "--value" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], value)) {
                    err << "bad --value\n";
                    return 1;
                }
                has_v = true;
                i += 1;
                continue;
            }
            if (args[i] == "--decimals" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], decimals_u64)) {
                    err << "bad --decimals\n";
                    return 1;
                }
                has_d = true;
                i += 1;
                continue;
            }
            if (args[i] == "--sig" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --sig\n";
                    return 1;
                }
                sig = *h;
                has_s = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }

        if (!has_f || !has_r || !has_h || !has_t || !has_v || !has_d || !has_s) {
            err << "missing params\n";
            return 1;
        }

        randio::GlobalState::Options opt;
        opt.storage.schema_version = 1;
        randio::GlobalState st(data_dir, opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }

        randio::module117::OracleReport r;
        r.feed = randio::module117::feed_id_from_name(feed_name);
        r.height = height;
        r.tick = tick;
        r.value_u64 = value;
        r.decimals = static_cast<std::uint32_t>(decimals_u64);
        r.reporter.id = reporter;
        r.signature = sig;

        randio::StateDelta d;
        const auto e = randio::module117::apply_report(st, r, d);
        const bool ok = (e == randio::module117::OracleError::OK);
        std::string j;
        j += "{\n";
        j += "  \"ok\": " + std::string(ok ? "true" : "false") + ",\n";
        j += "  \"err\": \"" + oracle_err_name(e) + "\",\n";
        j += "  \"feed_id\": \"" + crypto::to_hex(r.feed.id) + "\",\n";
        j += "  \"reporter_id\": \"" + crypto::to_hex(reporter) + "\"\n";
        j += "}\n";
        return emit(j, ok ? 0 : 1);
    }

    if (sub == "finalize") {
        std::string feed_name;
        std::uint64_t height = 0;
        std::uint64_t tick = 0;
        bool has_f = false;
        bool has_h = false;
        bool has_t = false;

        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--feed-name" && i + 1 < args.size()) {
                feed_name = std::string(args[i + 1]);
                has_f = true;
                i += 1;
                continue;
            }
            if (args[i] == "--height" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], height)) {
                    err << "bad --height\n";
                    return 1;
                }
                has_h = true;
                i += 1;
                continue;
            }
            if (args[i] == "--tick" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], tick)) {
                    err << "bad --tick\n";
                    return 1;
                }
                has_t = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }

        if (!has_f || !has_h || !has_t) {
            err << "missing params\n";
            return 1;
        }

        randio::GlobalState::Options opt;
        opt.storage.schema_version = 1;
        randio::GlobalState st(data_dir, opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }

        const auto feed = randio::module117::feed_id_from_name(feed_name);
        randio::StateDelta d;
        const auto e = randio::module117::finalize_price(st, feed, height, tick, d);
        const auto p = randio::module117::get_latest(st, feed);
        const bool ok = (e == randio::module117::OracleError::OK);

        std::string j;
        j += "{\n";
        j += "  \"ok\": " + std::string(ok ? "true" : "false") + ",\n";
        j += "  \"err\": \"" + oracle_err_name(e) + "\",\n";
        j += "  \"feed_id\": \"" + crypto::to_hex(feed.id) + "\"";
        if (p) {
            j += ",\n";
            j += "  \"height\": " + std::to_string(p->height) + ",\n";
            j += "  \"tick\": " + std::to_string(p->tick) + ",\n";
            j += "  \"value\": " + std::to_string(p->value_u64) + ",\n";
            j += "  \"decimals\": " + std::to_string(p->decimals) + ",\n";
            j += "  \"source_commit\": \"" + crypto::to_hex(p->source_commit) + "\"\n";
            j += "}\n";
        } else {
            j += "\n";
            j += "}\n";
        }
        return emit(j, ok ? 0 : 1);
    }

    if (sub == "latest") {
        std::string feed_name;
        bool has_f = false;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--feed-name" && i + 1 < args.size()) {
                feed_name = std::string(args[i + 1]);
                has_f = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has_f) {
            err << "missing --feed-name\n";
            return 1;
        }

        randio::GlobalState::Options opt;
        opt.storage.schema_version = 1;
        randio::GlobalState st(data_dir, opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }

        const auto feed = randio::module117::feed_id_from_name(feed_name);
        const auto p = randio::module117::get_latest(st, feed);

        std::string j;
        j += "{\n";
        j += "  \"ok\": true,\n";
        j += "  \"feed_id\": \"" + crypto::to_hex(feed.id) + "\",\n";
        if (!p) {
            j += "  \"latest\": null\n";
            j += "}\n";
            return emit(j, 0);
        }
        j += "  \"latest\": {\n";
        j += "    \"height\": " + std::to_string(p->height) + ",\n";
        j += "    \"tick\": " + std::to_string(p->tick) + ",\n";
        j += "    \"value\": " + std::to_string(p->value_u64) + ",\n";
        j += "    \"decimals\": " + std::to_string(p->decimals) + ",\n";
        j += "    \"source_commit\": \"" + crypto::to_hex(p->source_commit) + "\"\n";
        j += "  }\n";
        j += "}\n";
        return emit(j, 0);
    }

    if (sub == "history") {
        std::string feed_name;
        std::uint64_t limit_u64 = 0;
        bool has_f = false;
        bool has_l = false;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--feed-name" && i + 1 < args.size()) {
                feed_name = std::string(args[i + 1]);
                has_f = true;
                i += 1;
                continue;
            }
            if (args[i] == "--limit" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], limit_u64)) {
                    err << "bad --limit\n";
                    return 1;
                }
                has_l = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has_f || !has_l) {
            err << "missing params\n";
            return 1;
        }

        randio::GlobalState::Options opt;
        opt.storage.schema_version = 1;
        randio::GlobalState st(data_dir, opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }

        const auto feed = randio::module117::feed_id_from_name(feed_name);
        const auto hist = randio::module117::get_history(st, feed, static_cast<std::size_t>(limit_u64));

        std::string j;
        j += "{\n";
        j += "  \"ok\": true,\n";
        j += "  \"feed_id\": \"" + crypto::to_hex(feed.id) + "\",\n";
        j += "  \"history\": [\n";
        for (std::size_t i = 0; i < hist.size(); ++i) {
            const auto& p = hist[i];
            j += "    {\n";
            j += "      \"height\": " + std::to_string(p.height) + ",\n";
            j += "      \"tick\": " + std::to_string(p.tick) + ",\n";
            j += "      \"value\": " + std::to_string(p.value_u64) + ",\n";
            j += "      \"decimals\": " + std::to_string(p.decimals) + ",\n";
            j += "      \"source_commit\": \"" + crypto::to_hex(p.source_commit) + "\"\n";
            j += "    }";
            if (i + 1 < hist.size()) {
                j += ",";
            }
            j += "\n";
        }
        j += "  ]\n";
        j += "}\n";
        return emit(j, 0);
    }

    err << "unknown oracle subcommand\n";
    return 1;
}

[[nodiscard]] int cmd_proof(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }

    const auto sub = std::string(args[1]);

    if (sub == "export-account") {
        if (args.size() < 3) {
            print_usage(err);
            return 1;
        }
        const auto data_dir = std::filesystem::path(args[2]);

        std::uint64_t height = 0;
        std::string account;
        std::filesystem::path out_path;

        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--height" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], height)) {
                    err << "bad --height\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            if (args[i] == "--account" && i + 1 < args.size()) {
                account = std::string(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }

        if (height == 0 || account.empty() || out_path.empty()) {
            err << "missing params\n";
            return 1;
        }

        const auto hp = module88::extract_account_proof(data_dir, height, account);
        if (!hp) {
            err << "extract failed\n";
            return 1;
        }
        const auto bytes = module88::encode_historical_proof(*hp);
        const auto hex = bytes_to_hex(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
        if (!write_all(out_path, hex)) {
            err << "write failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    if (sub == "verify") {
        if (args.size() != 3) {
            print_usage(err);
            return 1;
        }
        const auto in_path = std::filesystem::path(args[2]);
        const auto txt = read_all(in_path);
        if (!txt) {
            err << "read failed\n";
            return 1;
        }
        const auto raw = bytes_from_hex(*txt);
        if (!raw) {
            err << "bad proof\n";
            return 1;
        }
        module88::DecodeOptions opt;
        const auto hp = module88::decode_historical_proof(std::span<const std::uint8_t>(raw->data(), raw->size()), opt);
        if (!hp) {
            err << "bad proof\n";
            return 1;
        }
        if (!module88::verify_historical_proof(*hp)) {
            err << "invalid proof\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    err << "unknown proof subcommand\n";
    return 1;
}

[[nodiscard]] int cmd_audit(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 3) {
        print_usage(err);
        return 1;
    }
    const auto sub = std::string(args[1]);
    const auto base_dir = std::filesystem::path(args[2]);
    const auto trace_path = base_dir / "logs" / "audit_trace.jsonl";

    if (sub == "export") {
        std::filesystem::path out_path;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (out_path.empty()) {
            err << "missing --out\n";
            return 1;
        }

        std::ifstream in(trace_path, std::ios::binary);
        if (!in.is_open()) {
            err << "read failed\n";
            return 1;
        }
        std::ofstream fout(out_path, std::ios::binary | std::ios::trunc);
        if (!fout.is_open()) {
            err << "write failed\n";
            return 1;
        }
        fout << in.rdbuf();
        fout.flush();
        if (!fout.good()) {
            err << "write failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    if (sub == "verify") {
        std::uint64_t from = 0;
        std::uint64_t to = 0;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--from" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], from)) {
                    err << "bad --from\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            if (args[i] == "--to" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], to)) {
                    err << "bad --to\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (from == 0 || to == 0 || to < from) {
            err << "missing params\n";
            return 1;
        }

        std::unordered_map<std::uint64_t, std::string> by_h;
        {
            std::ifstream in(trace_path, std::ios::binary);
            if (!in.is_open()) {
                err << "read failed\n";
                return 1;
            }
            std::string line;
            while (std::getline(in, line)) {
                const auto h = randio::audit::extract_height(line);
                if (!h) {
                    continue;
                }
                if (*h >= from && *h <= to) {
                    by_h[*h] = line;
                }
            }
        }
        for (std::uint64_t h = from; h <= to; ++h) {
            if (by_h.find(h) == by_h.end()) {
                err << "missing trace\n";
                return 1;
            }
        }

        const auto gtxt = read_all(base_dir / "genesis.json");
        if (!gtxt) {
            err << "read failed\n";
            return 1;
        }
        const auto max_supply = parse_json_u64_field(*gtxt, "max_supply");
        const auto alloc = parse_genesis_allocations(*gtxt);
        if (!max_supply || !alloc || alloc->empty()) {
            err << "bad genesis\n";
            return 1;
        }
        std::uint64_t total = 0;
        for (const auto& [_, amt] : *alloc) {
            total += amt;
        }

        const auto tmp_base = std::filesystem::temp_directory_path() / ("randium_audit_verify_" + crypto::to_hex(crypto::sha256(base_dir.string())));
        std::error_code ec;
        std::filesystem::remove_all(tmp_base, ec);
        ec.clear();
        std::filesystem::create_directories(tmp_base, ec);
        if (ec) {
            err << "mkdir failed\n";
            return 1;
        }

        GlobalState::Options gs_opt;
        gs_opt.storage.schema_version = 1;
        gs_opt.max_supply = *max_supply;
        GlobalState st(tmp_base / "state", gs_opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        StateDelta gd;
        if (!st.init_genesis_supply(total, *alloc, gd)) {
            err << "genesis init failed\n";
            return 1;
        }

        ChainDB::Options copt;
        copt.storage.schema_version = 1;
        copt.validation.max_tx_payload_bytes = 1024 * 1024;
        copt.validation.max_block_txs = 10000;
        copt.validation.max_tx_version = (std::numeric_limits<std::uint32_t>::max)();
        ChainDB db(tmp_base / "chain", copt);
        if (!db.open()) {
            err << "chain open failed\n";
            return 1;
        }

        if (!db.tip().has_value()) {
            Block genesis;
            genesis.header.version = 1;
            genesis.header.height = 0;
            genesis.header.prev_block = crypto::Hash256{};
            genesis.header.timestamp_unix_seconds = 0;
            genesis.header.nonce = 0;
            genesis.transactions = {};
            genesis.header.merkle_root = merkle_root(genesis.transactions);
            if (!db.put_genesis(genesis)) {
                err << "genesis put failed\n";
                return 1;
            }
            (void)db.set_state_root(0, st.state_root());
        }

        TransactionScheduler sched(TransactionScheduler::Options{1000, 4 * 1024 * 1024});
        DeterministicExecutor ex(DeterministicExecutor::Options{1});

        for (std::uint64_t h = from; h <= to; ++h) {
            const auto parsed = randio::audit::decode_jsonl(by_h[h]);
            if (!parsed || parsed->height != h) {
                err << "bad trace\n";
                return 1;
            }

            StateDelta ud;
            (void)st.apply_scheduled_upgrade(h, ud);

            Mempool::Options mp_opt;
            mp_opt.max_tx_version = static_cast<std::uint32_t>(st.protocol_version());
            Mempool mp(mp_opt);

            std::vector<Transaction> pool_raw;
            pool_raw.reserve(parsed->tx_results.size());

            for (const auto& tr : parsed->tx_results) {
                if (tr.tx_hex.empty()) {
                    continue;
                }
                const auto raw = bytes_from_hex(tr.tx_hex);
                if (!raw) {
                    err << "bad tx hex\n";
                    return 1;
                }
                const auto tx = randio::module67::decode_tx(std::span<const std::uint8_t>(raw->data(), raw->size()), randio::module67::DecodeOptions{1024 * 1024});
                if (!tx) {
                    err << "bad tx bytes\n";
                    return 1;
                }
                pool_raw.push_back(*tx);
                (void)mp.add(*tx);
            }

            const auto batch = sched.build_batch(mp);
            const auto plan = ExecutionPlanner::plan(batch);
            const auto before_root = st.state_root();
            const auto res = ex.execute(st, plan, h);

            std::vector<Transaction> applied_txs;
            for (const auto& id : res.applied) {
                for (const auto& tx : pool_raw) {
                    if (txid(tx) == id) {
                        applied_txs.push_back(tx);
                        break;
                    }
                }
            }
            std::sort(applied_txs.begin(), applied_txs.end(), [](const Transaction& a, const Transaction& b) { return txid(a) < txid(b); });

            const auto tip = db.tip();
            Block blk;
            blk.header.version = 1;
            blk.header.height = h;
            blk.header.prev_block = tip ? tip->hash : crypto::Hash256{};
            blk.header.timestamp_unix_seconds = h;
            blk.header.nonce = 0;
            blk.transactions = std::move(applied_txs);
            blk.header.merkle_root = merkle_root(blk.transactions);
            const auto bh = block_hash(blk.header);

            if (!db.add_block(blk)) {
                err << "add_block failed\n";
                return 1;
            }
            (void)db.set_state_root(h, st.state_root());

            randio::audit::BuildOptions bopt;
            bopt.max_keys_per_category = 200;
            bopt.include_changed_keys = true;
            const auto computed = randio::audit::from_execution(h,
                                                               blk.header.prev_block,
                                                               bh,
                                                               st.protocol_version(),
                                                               before_root,
                                                               st.state_root(),
                                                               res,
                                                               pool_raw,
                                                               bopt);
            randio::audit::EncodeOptions eopt;
            eopt.max_keys_per_category = bopt.max_keys_per_category;
            eopt.include_changed_keys = bopt.include_changed_keys;
            const auto canon_expected = randio::audit::encode_jsonl(*parsed, eopt);
            const auto canon_actual = randio::audit::encode_jsonl(computed, eopt);
            if (canon_expected != canon_actual) {
                err << "mismatch\n";
                return 1;
            }
        }

        out << "ok\n";
        return 0;
    }

    err << "unknown audit subcommand\n";
    return 1;
}

void append_u64_le(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

void append_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

[[nodiscard]] std::optional<std::uint64_t> decode_u64_le(std::span<const std::uint8_t> b) {
    if (b.size() != 8) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(b[static_cast<std::size_t>(i)]) << (8u * i));
    }
    return v;
}

[[nodiscard]] crypto::Hash256 contract_address_from_deploy_txid(const crypto::Hash256& txid) {
    return crypto::sha256(std::span<const std::uint8_t>(txid.data(), txid.size()));
}

[[nodiscard]] std::vector<std::uint8_t> code_marker(std::string_view name) {
    vm::Bytecode bc;
    bc.version = 1;
    bc.code.clear();
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    const auto h = crypto::sha256(name);
    bc.code.insert(bc.code.end(), h.begin(), h.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));
    return vm::VM::encode_bytecode(bc);
}

[[nodiscard]] Transaction make_deploy_tx(const std::string& deployer,
                                        const std::uint64_t expected_nonce,
                                        const std::uint64_t fee,
                                        const std::uint64_t gas_limit,
                                        const std::span<const std::uint8_t> code,
                                        const std::uint32_t version) {
    Transaction tx;
    tx.version = version;
    tx.nonce = expected_nonce;
    tx.fee = fee;

    std::vector<std::uint8_t> p;
    p.reserve(1 + 1 + deployer.size() + 8 + 4 + code.size());
    p.push_back(static_cast<std::uint8_t>(0x02));
    p.push_back(static_cast<std::uint8_t>(deployer.size()));
    p.insert(p.end(), deployer.begin(), deployer.end());
    append_u64_le(p, gas_limit);
    append_u32_le(p, static_cast<std::uint32_t>(code.size()));
    p.insert(p.end(), code.begin(), code.end());
    tx.payload = std::move(p);
    return tx;
}

[[nodiscard]] Transaction make_call_tx(const std::string& caller,
                                      const std::uint64_t expected_nonce,
                                      const std::uint64_t fee,
                                      const crypto::Hash256& contract,
                                      const std::uint64_t gas_limit,
                                      const std::span<const std::uint8_t> input,
                                      const std::uint32_t version) {
    Transaction tx;
    tx.version = version;
    tx.nonce = expected_nonce;
    tx.fee = fee;

    std::vector<std::uint8_t> p;
    p.reserve(1 + 1 + caller.size() + 32 + 8 + 4 + input.size());
    p.push_back(static_cast<std::uint8_t>(0x03));
    p.push_back(static_cast<std::uint8_t>(caller.size()));
    p.insert(p.end(), caller.begin(), caller.end());
    p.insert(p.end(), contract.begin(), contract.end());
    append_u64_le(p, gas_limit);
    append_u32_le(p, static_cast<std::uint32_t>(input.size()));
    p.insert(p.end(), input.begin(), input.end());
    tx.payload = std::move(p);
    return tx;
}

[[nodiscard]] int cmd_wallet(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);
[[nodiscard]] int cmd_audit(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);
[[nodiscard]] int cmd_proof(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);
[[nodiscard]] int cmd_oracle(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);

#if MOONRAND_ENABLE_MODULE108
[[nodiscard]] int cmd_sol(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);
#endif

void print_usage(std::ostream& out) {
    out << "Moonrand CLI\n";
    out << "Commands:\n";
    out << "  init-data-dir <data_dir>\n";
    out << "  config validate --config <file>\n";
    out << "  config keys\n";
    out << "  config print-defaults\n";
    out << "  config describe <key>\n";
    out << "  run-node <data_dir> --mode <validator|full|archive> [--id <id>] [--ticks N] [--perf]\n";
    out << "  state-root <data_dir>\n";
    out << "  checkpoint <data_dir>\n";
    out << "  genesis-generate <out_json> --network <devnet|testnet|mainnet> --max-supply <N> --alloc <id:amount> [--alloc <id:amount> ...]\n";
    out << "  genesis-freeze <genesis_json>\n";
    out << "  genesis-init <data_dir> --max-supply <N> --alloc <id:amount> [--alloc <id:amount> ...]\n";
    out << "  validator-onboard <data_dir> --network <devnet|testnet|mainnet> --genesis <genesis_json> --key <key_json> [--ticks N]\n";
    out << "  node-onboard <data_dir> --network <devnet|testnet|mainnet> --genesis <genesis_json> --mode <full|archive> [--ticks N]\n";
    out << "  rpc snapshot <data_dir> --out <file>\n";
    out << "  rpc getStatus <data_dir> [--out <file>]\n";
    out << "  rpc getSupply <data_dir> [--out <file>]\n";
    out << "  rpc getAccount <data_dir> --id <id> [--out <file>]\n";
    out << "  rpc getStateRoot <data_dir> [--height <H>] [--out <file>]\n";
    out << "  rpc getBlock <data_dir> --height <H> [--out <file>]\n";
    out << "  rpc getTx <data_dir> --txid <hex32> [--out <file>]\n";
    out << "  rpc getCheckpoint <data_dir> [--out <file>]\n";
    out << "  rpc eth-jsonrpc <data_dir> --in <file> [--out <file>]\n";
    out << "  explorer index <data_dir> --out <file>\n";
    out << "  devnet init <base_dir> --validators N --network <devnet|testnet> --max-supply <N> --balance-per-validator <N>\n";
    out << "  devnet reset <base_dir>\n";
    out << "  devnet spin-up <base_dir> [--ticks N]\n";
    out << "  devnet status <base_dir>\n";
    out << "  testnet presets\n";
    out << "  testnet init <base_dir> --validators N --max-supply <N> --balance-per-validator <N>\n";
    out << "  testnet status <base_dir>\n";
    out << "  incentnet presets\n";
    out << "  incentnet init <base_dir> --validators N --max-supply <N> --balance-per-validator <N> --reward-per-block <N>\n";
    out << "  incentnet status <base_dir>\n";
    out << "  validator-keygen --id <id> --seed <seed> --out <file>\n";
    out << "  validator-key-import --in <file>\n";
    out << "  validator-key-export --in <file> --out <file>\n";
    out << "  wallet create --id <id> --out <file>\n";
    out << "  wallet import --in <file>\n";
    out << "  wallet export --in <file> --out <file>\n";
    out << "  wallet balance <data_dir> --wallet <file>\n";
    out << "  wallet spv-balance <data_dir> --wallet <file>\n";
    out << "  wallet spv-sync <data_dir> --out <file>\n";
    out << "  wallet send <data_dir> --wallet <file> --to <id> --amount <N> [--fee <N>]\n";
    out << "  wallet status <data_dir>\n";
    out << "  audit export <data_dir> --out <file>\n";
    out << "  audit verify <data_dir> --from <height> --to <height>\n";
    out << "  proof export-account <data_dir> --height <H> --account <id> --out <file>\n";
    out << "  proof verify <file>\n";
    out << "  bridge verify-message <data_dir> --msg <file> --proof <file> [--out <file>]\n";
    out << "  bridge apply-wrap <data_dir> --msg <file> --proof <file> --wrap-action <mint|burn> [--out <file>]\n";
    out << "  bridge mark-seen <data_dir> --msg-id <hex64> [--out <file>]\n";
    out << "  bridge status <data_dir> (--msg-id <hex64> | --msg <file>) [--out <file>]\n";
    out << "  oracle feed-register <data_dir> --name <text> --decimals <u32> --max-history <u64> --min-quorum <u64> --max-deviation-bps <u64> [--enabled <true|false>] [--out <file>]\n";
    out << "  oracle reporter-register <data_dir> --id <hex64> --pubkey <hex64> --weight <u64> [--out <file>]\n";
    out << "  oracle report <data_dir> --feed-name <text> --reporter <hex64> --height <u64> --tick <u64> --value <u64> --decimals <u32> --sig <hex64> [--out <file>]\n";
    out << "  oracle finalize <data_dir> --feed-name <text> --height <u64> --tick <u64> [--out <file>]\n";
    out << "  oracle latest <data_dir> --feed-name <text> [--out <file>]\n";
    out << "  oracle history <data_dir> --feed-name <text> --limit <u64> [--out <file>]\n";
    out << "  tx decode --hex <tx_hex>\n";
    out << "  tx send <data_dir> --hex <tx_hex>\n";
    out << "  tx send <data_dir> --from <id> --to <id> --amount <N> --fee <N>\n";
    out << "  tx send-transfer <data_dir> --from <id> --to <id> --amount <N> --fee <N>\n";
    out << "  tx send-deploy <data_dir> --from <id> --fee <N> --gas <N> (--code-marker <RAND20|RANDNFT|STABLE118|AMM119|LEND119> | --code-hex <hex>)\n";
    out << "  tx send-call <data_dir> --from <id> --contract <hex32> --fee <N> --gas <N> (--input-hex <hex> | --rand20-mint --to <id> --amount <N> | --rand20-transfer --to <id> --amount <N> | --randnft-mint --to <id> [--meta <text>] | --randnft-transfer --to <id> --token-id <hex32>)\n";
#if MOONRAND_ENABLE_MODULE108
    out << "  sol compile --in <contract.sol> --contract <Name> --out-dir <dir>\n";
    out << "  sol deploy <data_dir> --from <id> --fee <N> --gas <N> --artifact <path.json>\n";
#endif
    out << "  query balance <data_dir> <id>\n";
    out << "  query nonce <data_dir> <id>\n";
    out << "  query account <data_dir> <id>\n";
    out << "  query supply <data_dir>\n";
    out << "  query state-root <data_dir>\n";
    out << "  query protocol-version <data_dir>\n";
    out << "  query halted <data_dir>\n";
    out << "  query contract-code <data_dir> --contract <hex32>\n";
    out << "  query contract-storage <data_dir> --contract <hex32> --key <hex32>\n";
    out << "  query contract-address <data_dir> --deploy-txid <hex32>\n";
    out << "  query rand20-supply <data_dir> --contract <hex32>\n";
    out << "  query rand20-balance <data_dir> --contract <hex32> --id <id>\n";
    out << "  query randnft-supply <data_dir> --contract <hex32>\n";
    out << "  query randnft-tokenid <data_dir> --contract <hex32> --serial <N>\n";
    out << "  query randnft-owner <data_dir> --contract <hex32> --token-id <hex32>\n";
    out << "  query randnft-meta <data_dir> --contract <hex32> --token-id <hex32>\n";
    out << "  query wrap-assets <data_dir>\n";
    out << "  query wrap-asset <data_dir> --asset <hex64>\n";
    out << "  query wrap-supply <data_dir> --asset <hex64>\n";
    out << "  query wrap-balance <data_dir> --asset <hex64> --account <hex64>\n";
    out << "  admin set-halted <data_dir> <true|false>\n";
    out << "  admin schedule-upgrade <data_dir> --version <u16> --height <u64>\n";
    out << "  admin show-upgrade <data_dir>\n";
    out << "  admin checkpoint-root <data_dir>\n";
    out << "  econ-sim <out_dir> <scenario> [--seed N] [--blocks N]\n";
    out << "  bench tps <data_dir> [--seed N] [--workload <transfer_only|rand20_heavy|mixed_contract_calls|mempool_ingest_stress>] [--blocks N]\n";
    out << "  bench rpc <data_dir> [--seed N]\n";
    out << "  bench all <data_dir> [--seed N] [--blocks N]\n";
    out << "  health <data_dir>\n";
    out << "  readiness <data_dir>\n";
    out << "Scenarios: fee_spam | stake_rotation | slashing_grief | cartel | reward_extract | partition\n";
    out << "\n";
}

#if MOONRAND_ENABLE_MODULE108
[[nodiscard]] int cmd_sol_compile(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    std::filesystem::path in_path;
    std::filesystem::path out_dir;
    std::string contract;

    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--in" && i + 1 < args.size()) {
            in_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--contract" && i + 1 < args.size()) {
            contract = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--out-dir" && i + 1 < args.size()) {
            out_dir = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (in_path.empty() || out_dir.empty() || contract.empty()) {
        err << "missing params\n";
        return 1;
    }

    const auto src = read_all(in_path);
    if (!src) {
        err << "read failed\n";
        return 1;
    }

    const auto art = randio::module108::compile_solidity_fallback(*src, in_path.generic_string(), contract);
    const auto out_path = out_dir / (contract + ".json");
    if (!randio::module108::write_artifact_file(out_path, art)) {
        err << "write failed\n";
        return 1;
    }

    out << "artifact=" << out_path.generic_string() << "\n";
    out << "bytecode_bytes=" << art.bytecode.size() << "\n";
    return 0;
}

[[nodiscard]] int cmd_sol_deploy(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    const auto data_dir = std::filesystem::path(args[1]);

    std::string from;
    std::uint64_t fee = 0;
    std::uint64_t gas = 0;
    std::filesystem::path artifact_path;

    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--from" && i + 1 < args.size()) {
            from = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--fee" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], fee)) {
                err << "bad --fee\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--gas" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], gas)) {
                err << "bad --gas\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--artifact" && i + 1 < args.size()) {
            artifact_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (from.empty() || gas == 0 || artifact_path.empty()) {
        err << "missing params\n";
        return 1;
    }

    const auto art = randio::module108::read_artifact_file(artifact_path);
    if (!art) {
        err << "bad artifact\n";
        return 1;
    }

    GlobalState::Options opt;
    opt.storage.schema_version = 1;
    GlobalState st(data_dir / "state", opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }
    const auto a = st.get_account(from);
    if (!a) {
        err << "missing from\n";
        return 1;
    }

    const auto tx = make_deploy_tx(from,
                                  a->nonce,
                                  fee,
                                  gas,
                                  std::span<const std::uint8_t>(art->bytecode.data(), art->bytecode.size()),
                                  static_cast<std::uint32_t>(st.protocol_version()));
    const auto bytes = serialize_tx(tx);
    const auto id = txid(tx);
    const auto name = crypto::to_hex(id);
    const auto contract_addr = contract_address_from_deploy_txid(id);

    std::error_code ec;
    const auto pool = data_dir / "txpool";
    std::filesystem::create_directories(pool, ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    const auto out_path = pool / ("tx_" + name + ".bin");
    std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        err << "write failed\n";
        return 1;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    f.flush();
    if (!f.good()) {
        err << "write failed\n";
        return 1;
    }

    out << "contract=" << crypto::to_hex(contract_addr) << "\n";
    out << "queued=" << name << "\n";
    return 0;
}

[[nodiscard]] int cmd_sol(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    if (args[1] == "compile") {
        return cmd_sol_compile(args.subspan(1), out, err);
    }
    if (args[1] == "deploy") {
        return cmd_sol_deploy(args.subspan(1), out, err);
    }
    err << "unknown sol subcommand\n";
    return 1;
}
#endif

[[nodiscard]] bool parse_bool_tf(std::string_view s, bool& out) {
    if (s == "true") {
        out = true;
        return true;
    }
    if (s == "false") {
        out = false;
        return true;
    }
    return false;
}

[[nodiscard]] bool parse_u16(std::string_view s, std::uint16_t& out) {
    std::uint64_t v = 0;
    if (!parse_u64(s, v)) {
        return false;
    }
    if (v > 65535) {
        return false;
    }
    out = static_cast<std::uint16_t>(v);
    return true;
}

[[nodiscard]] int cmd_node_onboard(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 8) {
        print_usage(err);
        return 1;
    }
    const auto data_dir = std::filesystem::path(args[1]);
    std::filesystem::path genesis_path;
    std::string network;
    std::string mode;
    std::uint64_t ticks = 1;
    std::uint32_t feature_flags = 0;
    std::uint64_t reward_per_block = 0;

    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--network" && i + 1 < args.size()) {
            network = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--genesis" && i + 1 < args.size()) {
            genesis_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--mode" && i + 1 < args.size()) {
            mode = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--ticks" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], ticks)) {
                err << "bad --ticks\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--features-staking") {
            feature_flags |= 0x1u;
            continue;
        }
        if (args[i] == "--features-slashing") {
            feature_flags |= 0x2u;
            continue;
        }
        if (args[i] == "--features-rewards") {
            feature_flags |= 0x4u;
            continue;
        }
        if (args[i] == "--reward-per-block" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], reward_per_block)) {
                err << "bad --reward-per-block\n";
                return 1;
            }
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (network.empty() || genesis_path.empty() || mode.empty()) {
        err << "missing params\n";
        return 1;
    }
    if (mode != "full" && mode != "archive") {
        err << "bad --mode\n";
        return 1;
    }
    const auto preset = preset_for(network);
    if (!preset) {
        err << "bad --network\n";
        return 1;
    }

    {
        std::ostringstream tmp_out;
        if (run_cli({"init-data-dir", data_dir.string()}, tmp_out, err) != 0) {
            return 1;
        }
    }

    const auto gtxt = read_all(genesis_path);
    if (!gtxt) {
        err << "read failed\n";
        return 1;
    }
    const auto max_supply = parse_json_u64_field(*gtxt, "max_supply");
    if (!max_supply) {
        err << "bad genesis\n";
        return 1;
    }
    const auto alloc = parse_genesis_allocations(*gtxt);
    if (!alloc || alloc->empty()) {
        err << "bad genesis\n";
        return 1;
    }

    const auto out_genesis = data_dir / "genesis.json";
    if (!write_all(out_genesis, *gtxt)) {
        err << "write failed\n";
        return 1;
    }
    {
        std::ostringstream tmp_out;
        if (run_cli({"genesis-freeze", out_genesis.string()}, tmp_out, err) != 0) {
            return 1;
        }
    }

    {
        std::uint64_t total = 0;
        for (const auto& [_, amt] : *alloc) {
            total += amt;
        }
        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        opt.max_supply = *max_supply;
        GlobalState st(data_dir / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        StateDelta d;
        if (!st.init_genesis_supply(total, *alloc, d)) {
            err << "genesis init failed\n";
            return 1;
        }

        std::vector<std::pair<ValidatorId, crypto::Hash256>> pubkeys;
        std::vector<std::pair<ValidatorId, std::uint64_t>> stakes;
        for (const auto& [id, amt] : *alloc) {
            if (id.size() >= 2 && id[0] == 'v') {
                const auto sec = crypto::sha256("validator:" + id + ":" + network);
                const auto kp = ValidatorKeypair::from_secret(sec);
                pubkeys.emplace_back(id, kp.pubkey);
                stakes.emplace_back(id, amt);
            }
        }
        if (!pubkeys.empty()) {
            StateDelta vd;
            (void)st.set_validator_set(pubkeys, stakes, vd);
        }
    }

    {
        std::string cfgj;
        cfgj += "{\n";
        cfgj += "  \"data_dir\": \"" + json_escape(data_dir.generic_string()) + "\",\n";
        cfgj += "  \"chain.id\": \"" + json_escape(preset->chain_id) + "\",\n";
        cfgj += "  \"chain.magic\": " + std::to_string(preset->chain_magic) + ",\n";
        cfgj += "  \"p2p.port\": " + std::to_string(preset->p2p_port) + ",\n";
        cfgj += "  \"rpc.port\": " + std::to_string(preset->rpc_port) + ",\n";
        if (feature_flags != 0) {
            cfgj += "  \"features.staking\": " + std::string((feature_flags & 0x1u) ? "true" : "false") + ",\n";
            cfgj += "  \"features.slashing\": " + std::string((feature_flags & 0x2u) ? "true" : "false") + ",\n";
            cfgj += "  \"features.rewards\": " + std::string((feature_flags & 0x4u) ? "true" : "false") + ",\n";
            cfgj += "  \"rewards.per_block\": " + std::to_string(reward_per_block) + ",\n";
        }
        cfgj += "  \"node.mode\": \"" + mode + "\",\n";
        cfgj += "  \"node.id\": \"\",\n";
        cfgj += "  \"node.ticks\": " + std::to_string(ticks) + "\n";
        cfgj += "}\n";
        if (!write_all(data_dir / "config.json", cfgj)) {
            err << "write failed\n";
            return 1;
        }
    }

    {
        std::ostringstream out2;
        std::ostringstream err2;
        if (run_cli({"run-node", data_dir.string(), "--config", (data_dir / "config.json").string(), "--ticks", "1"}, out2, err2) != 0) {
            err << err2.str();
            return 1;
        }
    }

    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_admin(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 3) {
        print_usage(err);
        return 1;
    }
    const auto sub = std::string(args[1]);
    const auto base = std::filesystem::path(args[2]);

    if (sub == "set-halted") {
        if (args.size() != 4) {
            print_usage(err);
            return 1;
        }
        bool on = false;
        if (!parse_bool_tf(args[3], on)) {
            err << "bad value\n";
            return 1;
        }
        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        GlobalState st(base / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        StateDelta d;
        if (!st.set_halted(on, d)) {
            err << "set_halted failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    if (sub == "schedule-upgrade") {
        std::uint16_t ver = 0;
        std::uint64_t height = 0;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--version" && i + 1 < args.size()) {
                if (!parse_u16(args[i + 1], ver)) {
                    err << "bad --version\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            if (args[i] == "--height" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], height)) {
                    err << "bad --height\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (ver == 0 || height == 0) {
            err << "missing params\n";
            return 1;
        }
        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        GlobalState st(base / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        StateDelta d;
        if (!st.schedule_upgrade(ver, height, d)) {
            err << "schedule_upgrade failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    if (sub == "show-upgrade") {
        if (args.size() != 3) {
            print_usage(err);
            return 1;
        }
        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        GlobalState st(base / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        const auto sch = st.scheduled_upgrade();
        if (!sch) {
            out << "none\n";
            return 0;
        }
        out << "version=" << sch->first << " height=" << sch->second << "\n";
        return 0;
    }

    if (sub == "checkpoint-root") {
        if (args.size() != 3) {
            print_usage(err);
            return 1;
        }
        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        GlobalState st(base / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        const auto chk = st.checkpoint_root();
        if (!chk) {
            out << "none\n";
            return 0;
        }
        out << crypto::to_hex(*chk) << "\n";
        return 0;
    }

    err << "unknown admin subcommand\n";
    return 1;
}

[[nodiscard]] int cmd_rpc_snapshot(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 3) {
        print_usage(err);
        return 1;
    }
    const auto sub = std::string(args[1]);
    const auto data_dir = std::filesystem::path(args[2]);

    std::filesystem::path out_path;
    std::filesystem::path in_path;
    std::string body;
    std::uint64_t height = (std::numeric_limits<std::uint64_t>::max)();
    std::uint64_t from_h = 0;
    std::uint64_t to_h = (std::numeric_limits<std::uint64_t>::max)();
    std::uint64_t limit_u64 = 1000;
    std::string id;
    crypto::Hash256 want_txid{};
    bool has_txid = false;

    crypto::Hash256 want_addr{};
    bool has_addr = false;
    crypto::Hash256 want_topic[4]{};
    bool has_topic[4]{false, false, false, false};

    for (std::size_t i = 3; i < args.size(); ++i) {
        if (args[i] == "--out" && i + 1 < args.size()) {
            out_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--in" && i + 1 < args.size()) {
            in_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--body" && i + 1 < args.size()) {
            body = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--height" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], height)) {
                err << "bad --height\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--from" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], from_h)) {
                err << "bad --from\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--to" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], to_h)) {
                err << "bad --to\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--limit" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], limit_u64)) {
                err << "bad --limit\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--address" && i + 1 < args.size()) {
            const auto h = hash256_from_hex(args[i + 1]);
            if (!h) {
                err << "bad --address\n";
                return 1;
            }
            want_addr = *h;
            has_addr = true;
            i += 1;
            continue;
        }
        if (args[i] == "--topic0" && i + 1 < args.size()) {
            const auto h = hash256_from_hex(args[i + 1]);
            if (!h) {
                err << "bad --topic0\n";
                return 1;
            }
            want_topic[0] = *h;
            has_topic[0] = true;
            i += 1;
            continue;
        }
        if (args[i] == "--topic1" && i + 1 < args.size()) {
            const auto h = hash256_from_hex(args[i + 1]);
            if (!h) {
                err << "bad --topic1\n";
                return 1;
            }
            want_topic[1] = *h;
            has_topic[1] = true;
            i += 1;
            continue;
        }
        if (args[i] == "--topic2" && i + 1 < args.size()) {
            const auto h = hash256_from_hex(args[i + 1]);
            if (!h) {
                err << "bad --topic2\n";
                return 1;
            }
            want_topic[2] = *h;
            has_topic[2] = true;
            i += 1;
            continue;
        }
        if (args[i] == "--topic3" && i + 1 < args.size()) {
            const auto h = hash256_from_hex(args[i + 1]);
            if (!h) {
                err << "bad --topic3\n";
                return 1;
            }
            want_topic[3] = *h;
            has_topic[3] = true;
            i += 1;
            continue;
        }
        if (args[i] == "--id" && i + 1 < args.size()) {
            id = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--txid" && i + 1 < args.size()) {
            const auto h = hash256_from_hex(args[i + 1]);
            if (!h) {
                err << "bad --txid\n";
                return 1;
            }
            want_txid = *h;
            has_txid = true;
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    auto decode_index_bytes = [](const std::vector<std::uint8_t>& bytes) -> std::optional<std::vector<std::string>> {
        auto read_u32_le = [](const std::uint8_t* p) -> std::uint32_t {
            return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
                   (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
        };
        if (bytes.size() < 4) {
            return std::nullopt;
        }

        std::size_t off = 0;
        const auto count = read_u32_le(bytes.data());
        off += 4;

        std::vector<std::string> idx;
        idx.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            if (off + 4 > bytes.size()) {
                return std::nullopt;
            }
            const auto len = read_u32_le(bytes.data() + off);
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
    };

    auto build_merkle_proof = [](const std::vector<crypto::Hash256>& leaves, const std::size_t leaf_index) -> std::optional<module80::MerkleProof> {
        if (leaves.empty()) {
            return std::nullopt;
        }
        if (leaf_index >= leaves.size()) {
            return std::nullopt;
        }

        module80::MerkleProof mp;
        mp.leaf_index = static_cast<std::uint64_t>(leaf_index);
        mp.leaf_count = static_cast<std::uint64_t>(leaves.size());
        mp.siblings.clear();

        std::vector<crypto::Hash256> layer = leaves;
        std::size_t idx = leaf_index;
        while (layer.size() > 1) {
            crypto::Hash256 sib{};
            if ((idx % 2u) == 0u) {
                sib = (idx + 1u < layer.size()) ? layer[idx + 1u] : layer[idx];
            } else {
                sib = layer[idx - 1u];
            }
            mp.siblings.push_back(sib);

            std::vector<crypto::Hash256> next;
            next.reserve((layer.size() + 1) / 2);
            for (std::size_t i = 0; i < layer.size(); i += 2) {
                const auto& left = layer[i];
                const auto& right = (i + 1 < layer.size()) ? layer[i + 1] : layer[i];
                next.push_back(module80::merkle_parent(left, right));
            }
            layer = std::move(next);
            idx /= 2u;
        }

        if (mp.siblings.size() != module80::merkle_depth(mp.leaf_count)) {
            return std::nullopt;
        }

        return mp;
    };

    ChainDB::Options copt;
    copt.storage.schema_version = 1;
    ChainDB db(data_dir / "chain", copt);
    if (!db.open()) {
        err << "chain open failed\n";
        return 1;
    }
    const auto tip = db.tip();

    GlobalState::Options gs;
    gs.storage.schema_version = 1;
    GlobalState st(data_dir / "state", gs);
    const bool state_ok = st.open();

    cfg::LoadResult cfg_res;
    {
        const auto cfgp = data_dir / "config.json";
        if (std::filesystem::exists(cfgp)) {
            cfg_res = cfg::load(std::optional<std::filesystem::path>(cfgp), std::nullopt);
        } else {
            cfg_res.cfg = cfg::defaults();
        }
    }

    std::string j;
    if (sub == "snapshot" || sub == "getStatus") {
        j += "{\n";
        j += "  \"chain.id\": \"" + json_escape(cfg_res.cfg.chain_id) + "\",\n";
        j += "  \"chain.magic\": " + std::to_string(cfg_res.cfg.chain_magic) + ",\n";
        j += "  \"height\": " + std::to_string(tip ? tip->height : 0) + ",\n";
        j += "  \"tip_hash\": \"" + (tip ? crypto::to_hex(tip->hash) : std::string(64, '0')) + "\",\n";
        j += "  \"state_root\": \"" + crypto::to_hex(st.state_root()) + "\",\n";
        j += "  \"protocol_version\": " + std::to_string(st.protocol_version()) + ",\n";
        j += "  \"halted\": " + std::string(st.halted() ? "true" : "false") + ",\n";
        const auto sch = st.scheduled_upgrade();
        if (sch) {
            j += "  \"scheduled_upgrade\": {\"version\": " + std::to_string(sch->first) + ", \"height\": " + std::to_string(sch->second) + "}\n";
        } else {
            j += "  \"scheduled_upgrade\": null\n";
        }
        j += "}\n";
    } else if (sub == "eth-jsonrpc") {
        std::string req;
        if (!body.empty()) {
            req = body;
        } else if (!in_path.empty()) {
            const auto t = read_all(in_path);
            if (!t) {
                err << "read failed\n";
                return 1;
            }
            req = *t;
        } else {
            err << "missing --in or --body\n";
            return 1;
        }
        j = randio::eth::handle_eth_jsonrpc(db, st, cfg_res.cfg, req) + "\n";
    } else if (sub == "getSupply") {
        j += "{\n";
        j += "  \"minted_total\": " + std::to_string(st.minted_total() ? *st.minted_total() : 0) + ",\n";
        j += "  \"burned_total\": " + std::to_string(st.burned_total() ? *st.burned_total() : 0) + ",\n";
        j += "  \"circulating_supply\": " + std::to_string(st.circulating_supply() ? *st.circulating_supply() : 0) + "\n";
        j += "}\n";
    } else if (sub == "getAccount") {
        if (id.empty()) {
            err << "missing --id\n";
            return 1;
        }
        const auto a = st.get_account(id);
        if (!a) {
            j = "null\n";
        } else {
            j += "{\n";
            j += "  \"id\": \"" + json_escape(id) + "\",\n";
            j += "  \"balance\": " + std::to_string(a->balance) + ",\n";
            j += "  \"nonce\": " + std::to_string(a->nonce) + "\n";
            j += "}\n";
        }
    } else if (sub == "getStateRoot") {
        if (height == (std::numeric_limits<std::uint64_t>::max)()) {
            j = "\"" + crypto::to_hex(st.state_root()) + "\"\n";
        } else {
            const auto r = db.state_root_by_height(height);
            if (!r) {
                j = "null\n";
            } else {
                j = "\"" + crypto::to_hex(*r) + "\"\n";
            }
        }
    } else if (sub == "getBlock") {
        if (height == (std::numeric_limits<std::uint64_t>::max)()) {
            err << "missing --height\n";
            return 1;
        }
        const auto b = db.block_by_height(height);
        if (!b) {
            j = "null\n";
        } else {
            const auto bh = block_hash(b->header);
            j += "{\n";
            j += "  \"height\": " + std::to_string(b->header.height) + ",\n";
            j += "  \"hash\": \"" + crypto::to_hex(bh) + "\",\n";
            j += "  \"prev\": \"" + crypto::to_hex(b->header.prev_block) + "\",\n";
            j += "  \"txids\": [";
            for (std::size_t i = 0; i < b->transactions.size(); ++i) {
                const auto tid = txid(b->transactions[i]);
                j += "\"" + crypto::to_hex(tid) + "\"";
                j += (i + 1 == b->transactions.size()) ? "" : ",";
            }
            j += "]\n";
            j += "}\n";
        }
    } else if (sub == "getTx") {
        if (!has_txid) {
            err << "missing --txid\n";
            return 1;
        }
        const auto maxh = tip ? tip->height : 0;
        bool found = false;
        std::uint64_t fh = 0;
        Transaction ftx;
        for (std::uint64_t h = 0; h <= maxh; ++h) {
            const auto blk = db.block_by_height(h);
            if (!blk) {
                continue;
            }
            for (const auto& tx : blk->transactions) {
                const auto tid = txid(tx);
                if (tid == want_txid) {
                    found = true;
                    fh = h;
                    ftx = tx;
                    break;
                }
            }
            if (found) {
                break;
            }
        }
        if (!found) {
            j = "null\n";
        } else {
            j += "{\n";
            j += "  \"txid\": \"" + crypto::to_hex(want_txid) + "\",\n";
            j += "  \"height\": " + std::to_string(fh) + ",\n";
            j += "  \"version\": " + std::to_string(ftx.version) + ",\n";
            j += "  \"nonce\": " + std::to_string(ftx.nonce) + ",\n";
            j += "  \"fee\": " + std::to_string(ftx.fee) + ",\n";
            j += "  \"payload_hex\": \"" + bytes_to_hex(std::span<const std::uint8_t>(ftx.payload.data(), ftx.payload.size())) + "\"\n";
            j += "}\n";
        }
    } else if (sub == "getLogs") {
        const auto maxh = tip ? tip->height : 0;
        const auto to = (to_h == (std::numeric_limits<std::uint64_t>::max)() || to_h > maxh) ? maxh : to_h;

        module106::TopicFilter filt;
        if (has_addr) {
            filt.address = want_addr;
        }
        for (int i = 0; i < 4; ++i) {
            if (has_topic[i]) {
                filt.topics[static_cast<std::size_t>(i)] = std::vector<crypto::Hash256>{want_topic[i]};
            }
        }

        module106::DecodeOptions dopt;
        dopt.max_topics = 4;
        dopt.max_data_bytes = 256 * 1024;

        const std::size_t limit = (limit_u64 > 100000) ? 100000 : static_cast<std::size_t>(limit_u64);

        if (limit == 0 || from_h > maxh || from_h > to) {
            j = "[]\n";
        } else {
            const auto from = from_h;

            j += "[";
            std::size_t emitted = 0;
            bool first = true;

            for (std::uint64_t h = from; h <= to; ++h) {
                const auto blk = db.block_by_height(h);
                if (!blk) {
                    continue;
                }

                for (const auto& tx : blk->transactions) {
                    const auto tid = txid(tx);
                    const auto cnt_raw = st.get_storage_entry(module106::log_count_key(tid));
                    if (!cnt_raw) {
                        continue;
                    }
                    const auto cnt = module106::decode_u64_le(std::span<const std::uint8_t>(cnt_raw->data(), cnt_raw->size()));
                    if (!cnt) {
                        continue;
                    }
                    if (*cnt > 10000) {
                        continue;
                    }

                    for (std::uint64_t i = 0; i < *cnt; ++i) {
                        const auto entry_raw = st.get_storage_entry(module106::log_entry_key(tid, static_cast<std::uint32_t>(i)));
                        if (!entry_raw) {
                            continue;
                        }
                        module106::LogRecord rec;
                        std::size_t consumed = 0;
                        const auto stc = module106::decode_log_record(std::span<const std::uint8_t>(entry_raw->data(), entry_raw->size()), rec, consumed, dopt);
                        if (stc != module106::DecodeStatus::Ok || consumed != entry_raw->size()) {
                            continue;
                        }
                        if (!module106::matches(rec, filt)) {
                            continue;
                        }

                        if (emitted >= limit) {
                            break;
                        }

                        if (!first) {
                            j += ",";
                        }
                        first = false;
                        j += "{";
                        j += "\"height\":" + std::to_string(h) + ",";
                        j += "\"txid\":\"" + crypto::to_hex(tid) + "\",";
                        j += "\"log_index\":" + std::to_string(i) + ",";
                        j += "\"address\":\"" + crypto::to_hex(rec.address) + "\",";
                        j += "\"topics\":[";
                        for (std::size_t ti = 0; ti < rec.topics.size(); ++ti) {
                            j += "\"" + crypto::to_hex(rec.topics[ti]) + "\"";
                            j += (ti + 1 == rec.topics.size()) ? "" : ",";
                        }
                        j += "],";
                        j += "\"data_hex\":\"" + bytes_to_hex(std::span<const std::uint8_t>(rec.data.data(), rec.data.size())) + "\"";
                        j += "}";
                        emitted += 1;
                    }
                    if (emitted >= limit) {
                        break;
                    }
                }
                if (emitted >= limit) {
                    break;
                }
                if (h == to) {
                    break;
                }
            }
            j += "]\n";
        }
    } else if (sub == "getTxProof") {
        if (!has_txid) {
            err << "missing --txid\n";
            return 1;
        }

        const auto maxh = tip ? tip->height : 0;
        bool found = false;
        std::uint64_t fh = 0;
        Transaction ftx;
        std::size_t fidx = 0;
        BlockHeader fhdr;

        for (std::uint64_t h = 0; h <= maxh; ++h) {
            const auto blk = db.block_by_height(h);
            if (!blk) {
                continue;
            }
            for (std::size_t i = 0; i < blk->transactions.size(); ++i) {
                const auto tid = txid(blk->transactions[i]);
                if (tid == want_txid) {
                    found = true;
                    fh = h;
                    ftx = blk->transactions[i];
                    fidx = i;
                    fhdr = blk->header;
                    break;
                }
            }
            if (found) {
                break;
            }
        }

        if (!found) {
            j = "null\n";
        } else {
            std::vector<crypto::Hash256> txids;
            {
                const auto blk = db.block_by_height(fh);
                if (!blk) {
                    j = "null\n";
                } else {
                    txids.reserve(blk->transactions.size());
                    for (const auto& tx : blk->transactions) {
                        txids.push_back(txid(tx));
                    }
                }
            }

            if (txids.empty()) {
                j = "null\n";
            } else {
                const auto mp = build_merkle_proof(txids, fidx);
                if (!mp) {
                    j = "null\n";
                } else {
                    module80::TxInclusionProof p;
                    p.header = fhdr;
                    p.tx = ftx;
                    p.merkle = *mp;
                    const auto pb = module80::encode_tx_inclusion_proof(p);
                    j = "\"" + bytes_to_hex(std::span<const std::uint8_t>(pb.data(), pb.size())) + "\"\n";
                }
            }
        }
    } else if (sub == "getAccountProof") {
        if (id.empty()) {
            err << "missing --id\n";
            return 1;
        }

        const auto a = st.get_account(id);
        if (!a) {
            j = "null\n";
        } else {
            const auto th = tip ? tip->height : 0;
            const auto want_h = (height == (std::numeric_limits<std::uint64_t>::max)()) ? th : height;
            if (want_h != th) {
                j = "null\n";
            } else {
                Storage::Options sopt;
                sopt.schema_version = 1;
                Storage stor(data_dir / "state", sopt);
                if (!stor.open()) {
                    j = "null\n";
                } else {
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
                        j = "null\n";
                    } else {
                        std::vector<crypto::Hash256> leaves;
                        leaves.reserve(aidx->size() + cidx->size() + sidx->size() + 8);

                        std::optional<std::size_t> account_leaf_pos;

                        auto read_u64_le = [](const std::uint8_t* p) -> std::uint64_t {
                            std::uint64_t v = 0;
                            for (int i = 0; i < 8; ++i) {
                                v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
                            }
                            return v;
                        };

                        for (const auto& aid : *aidx) {
                            const auto raw = stor.get("acct:" + aid);
                            if (!raw || raw->size() != 16) {
                                continue;
                            }
                            Account aa;
                            aa.nonce = read_u64_le(raw->data());
                            aa.balance = read_u64_le(raw->data() + 8);
                            if (aid == id) {
                                account_leaf_pos = leaves.size();
                            }
                            leaves.push_back(module80::account_leaf_hash(aid, aa));
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
                            leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
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
                            leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
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
                            leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
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
                            leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
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
                            leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
                        }

                        if (!account_leaf_pos.has_value()) {
                            j = "null\n";
                        } else {
                            const auto computed_root = [&]() -> crypto::Hash256 {
                                if (leaves.empty()) {
                                    return crypto::sha256(std::string_view{});
                                }
                                std::vector<crypto::Hash256> layer = leaves;
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
                            }();

                            const auto sr = st.state_root();
                            if (computed_root != sr) {
                                j = "null\n";
                            } else {
                                const auto mp = build_merkle_proof(leaves, *account_leaf_pos);
                                if (!mp) {
                                    j = "null\n";
                                } else {
                                    module80::AccountProof p;
                                    p.height = want_h;
                                    p.state_root = sr;
                                    p.id = id;
                                    p.account = *a;
                                    p.merkle = *mp;
                                    const auto pb = module80::encode_account_proof(p);
                                    j = "\"" + bytes_to_hex(std::span<const std::uint8_t>(pb.data(), pb.size())) + "\"\n";
                                }
                            }
                        }
                    }
                }
            }
        }
    } else if (sub == "getReceiptProof") {
        j = "null\n";
    } else if (sub == "getCheckpoint") {
        const auto raw = st.latest_signed_checkpoint_bytes();
        if (!raw) {
            j = "null\n";
        } else {
            const auto cp = randio::consensus::decode_signed_checkpoint(std::span<const std::uint8_t>(raw->data(), raw->size()));
            if (!cp) {
                j = "null\n";
            } else {
                j += "{\n";
                j += "  \"height\": " + std::to_string(cp->header.height) + ",\n";
                j += "  \"block_hash\": \"" + crypto::to_hex(cp->header.block_hash) + "\",\n";
                j += "  \"state_root\": \"" + crypto::to_hex(cp->header.state_root) + "\",\n";
                j += "  \"protocol_version\": " + std::to_string(cp->header.protocol_version) + ",\n";
                j += "  \"signatures\": [";
                for (std::size_t i = 0; i < cp->signatures.size(); ++i) {
                    j += "{\"validator_id\": \"" + json_escape(cp->signatures[i].validator_id) + "\", \"signature\": \"" + crypto::to_hex(cp->signatures[i].signature) + "\"}";
                    j += (i + 1 == cp->signatures.size()) ? "" : ",";
                }
                j += "]\n";
                j += "}\n";
            }
        }
    } else {
        err << "unknown rpc subcommand\n";
        return 1;
    }

    if (!out_path.empty()) {
        if (!write_all(out_path, j)) {
            err << "write failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }
    out << j;
    return 0;
}

[[nodiscard]] int cmd_explorer_index(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 4) {
        print_usage(err);
        return 1;
    }
    if (args[1] != "index") {
        err << "unknown explorer subcommand\n";
        return 1;
    }
    const auto data_dir = std::filesystem::path(args[2]);
    std::filesystem::path out_path;
    for (std::size_t i = 3; i < args.size(); ++i) {
        if (args[i] == "--out" && i + 1 < args.size()) {
            out_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }
    if (out_path.empty()) {
        err << "missing --out\n";
        return 1;
    }

    ChainDB::Options copt;
    copt.storage.schema_version = 1;
    ChainDB db(data_dir / "chain", copt);
    if (!db.open()) {
        err << "chain open failed\n";
        return 1;
    }
    const auto tip = db.tip();
    const auto maxh = tip ? tip->height : 0;
    std::string j;
    j += "{\n";
    j += "  \"height\": " + std::to_string(maxh) + ",\n";
    j += "  \"blocks\": [\n";
    for (std::uint64_t h = 0; h <= maxh; ++h) {
        const auto hdr = db.header_by_height(h);
        if (!hdr) {
            continue;
        }
        const auto bh = block_hash(*hdr);
        j += "    {\"height\": " + std::to_string(h) + ", \"hash\": \"" + crypto::to_hex(bh) + "\"}";
        j += (h == maxh) ? "\n" : ",\n";
    }
    j += "  ]\n";
    j += "}\n";
    if (!write_all(out_path, j)) {
        err << "write failed\n";
        return 1;
    }
    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_devnet_init(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    if (args.size() < 3 || args[1] != "init") {
        err << "unknown devnet subcommand\n";
        return 1;
    }
    const auto base_dir = std::filesystem::path(args[2]);
    std::uint64_t validators = 0;
    std::uint64_t max_supply = 0;
    std::uint64_t per_val = 0;
    std::string network = "devnet";

    for (std::size_t i = 3; i < args.size(); ++i) {
        if (args[i] == "--validators" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], validators)) {
                err << "bad --validators\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--network" && i + 1 < args.size()) {
            network = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--max-supply" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], max_supply)) {
                err << "bad --max-supply\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--balance-per-validator" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], per_val)) {
                err << "bad --balance-per-validator\n";
                return 1;
            }
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (validators == 0 || max_supply == 0 || per_val == 0) {
        err << "missing params\n";
        return 1;
    }
    if (network != "devnet" && network != "testnet") {
        err << "bad --network\n";
        return 1;
    }
    const auto preset = preset_for(network);
    if (!preset) {
        err << "bad --network\n";
        return 1;
    }

    std::vector<std::pair<std::string, std::uint64_t>> alloc;
    alloc.reserve(static_cast<std::size_t>(validators) + 1);
    std::uint64_t allocated = 0;
    for (std::uint64_t i = 1; i <= validators; ++i) {
        const auto id = "v" + std::to_string(i);
        alloc.emplace_back(id, per_val);
        allocated += per_val;
    }
    if (allocated < max_supply) {
        alloc.emplace_back("faucet", max_supply - allocated);
    }

    std::error_code ec;
    std::filesystem::create_directories(base_dir, ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }

    const auto gpath = base_dir / "genesis.json";
    const auto gtxt = make_genesis_json(preset->chain_id,
                                        preset->chain_magic,
                                        preset->p2p_port,
                                        preset->rpc_port,
                                        max_supply,
                                        alloc);
    if (!write_all(gpath, gtxt)) {
        err << "write failed\n";
        return 1;
    }
    {
        std::ostringstream tmp_out;
        if (run_cli({"genesis-freeze", gpath.string()}, tmp_out, err) != 0) {
            return 1;
        }
    }

    const auto nodes_dir = base_dir / "nodes";
    std::filesystem::create_directories(nodes_dir, ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }

    for (std::uint64_t i = 1; i <= validators; ++i) {
        const auto id = "v" + std::to_string(i);
        const auto keyp = base_dir / (id + ".key.json");
        {
            std::ostringstream tmp_out;
            std::ostringstream tmp_err;
            if (run_cli({"validator-keygen", "--id", id, "--seed", network, "--out", keyp.string()}, tmp_out, tmp_err) != 0) {
                err << tmp_err.str();
                return 1;
            }
        }

        const auto vdir = nodes_dir / id;
        std::ostringstream tmp_out;
        std::ostringstream tmp_err;
        if (run_cli({"validator-onboard",
                     vdir.string(),
                     "--network",
                     network,
                     "--genesis",
                     gpath.string(),
                     "--key",
                     keyp.string(),
                     "--ticks",
                     "1"},
                    tmp_out,
                    tmp_err)
            != 0) {
            err << tmp_err.str();
            return 1;
        }
    }

    {
        const auto fdir = nodes_dir / "full1";
        std::ostringstream tmp_out;
        std::ostringstream tmp_err;
        if (run_cli({"node-onboard",
                     fdir.string(),
                     "--network",
                     network,
                     "--genesis",
                     gpath.string(),
                     "--mode",
                     "full",
                     "--ticks",
                     "1"},
                    tmp_out,
                    tmp_err)
            != 0) {
            err << tmp_err.str();
            return 1;
        }
    }
    {
        const auto adir = nodes_dir / "archive1";
        std::ostringstream tmp_out;
        std::ostringstream tmp_err;
        if (run_cli({"node-onboard",
                     adir.string(),
                     "--network",
                     network,
                     "--genesis",
                     gpath.string(),
                     "--mode",
                     "archive",
                     "--ticks",
                     "1"},
                    tmp_out,
                    tmp_err)
            != 0) {
            err << tmp_err.str();
            return 1;
        }
    }

    {
        std::filesystem::create_directories(base_dir / "rpc", ec);
        std::filesystem::create_directories(base_dir / "explorer", ec);
        std::ostringstream tmp_out;
        std::ostringstream tmp_err;
        if (run_cli({"rpc",
                     "snapshot",
                     (nodes_dir / "full1").string(),
                     "--out",
                     (base_dir / "rpc" / "status.json").string()},
                    tmp_out,
                    tmp_err)
            != 0) {
            err << tmp_err.str();
            return 1;
        }
        std::ostringstream tmp_out2;
        std::ostringstream tmp_err2;
        if (run_cli({"explorer",
                     "index",
                     (nodes_dir / "full1").string(),
                     "--out",
                     (base_dir / "explorer" / "index.json").string()},
                    tmp_out2,
                    tmp_err2)
            != 0) {
            err << tmp_err2.str();
            return 1;
        }
    }

    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_config_keys(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() != 1) {
        print_usage(err);
        return 1;
    }
    auto ks = cfg::keys();
    std::sort(ks.begin(), ks.end(), [](std::string_view a, std::string_view b) { return a < b; });
    for (const auto k : ks) {
        out << k << "\n";
    }
    return 0;
}

[[nodiscard]] int cmd_config_print_defaults(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() != 1) {
        print_usage(err);
        return 1;
    }
    out << cfg::print_defaults_json();
    return 0;
}

[[nodiscard]] int cmd_config_describe(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() != 2) {
        print_usage(err);
        return 1;
    }
    const auto d = cfg::describe(args[1]);
    if (!d) {
        err << "unknown key\n";
        return 1;
    }
    out << args[1] << ": " << *d << "\n";
    return 0;
}

[[nodiscard]] std::optional<std::filesystem::path> parse_config_path(std::span<const std::string_view> args, std::ostream& err) {
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--config" && i + 1 < args.size()) {
            return std::filesystem::path(args[i + 1]);
        }
    }
    (void)err;
    return std::nullopt;
}

[[nodiscard]] bool parse_u64(std::string_view s, std::uint64_t& out);
[[nodiscard]] std::optional<Transaction> parse_tx_bytes(std::span<const std::uint8_t> bytes);

struct LoadedKey final {
    ValidatorId id;
    ValidatorKeypair kp;
};

struct WalletFile final {
    std::string id;
};

[[nodiscard]] std::optional<LoadedKey> read_key_file(const std::filesystem::path& p);

[[nodiscard]] bool write_wallet_file(const std::filesystem::path& p, std::string_view id) {
    std::string out;
    out += "{\n";
    out += "  \"id\": \"" + json_escape(id) + "\"\n";
    out += "}\n";
    return write_all(p, out);
}

[[nodiscard]] std::optional<WalletFile> read_wallet_file(const std::filesystem::path& p) {
    const auto s = read_all(p);
    if (!s) {
        return std::nullopt;
    }
    const auto id = json_get_string(*s, "id");
    if (!id || id->empty()) {
        return std::nullopt;
    }
    WalletFile w;
    w.id = *id;
    return w;
}

[[nodiscard]] int cmd_wallet(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    const auto sub = std::string(args[1]);

    if (sub == "create") {
        std::string id;
        std::filesystem::path out_path;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--id" && i + 1 < args.size()) {
                id = std::string(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (id.empty() || out_path.empty()) {
            err << "missing params\n";
            return 1;
        }
        if (!write_wallet_file(out_path, id)) {
            err << "write failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    if (sub == "import") {
        std::filesystem::path in_path;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--in" && i + 1 < args.size()) {
                in_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (in_path.empty()) {
            err << "missing --in\n";
            return 1;
        }
        const auto w = read_wallet_file(in_path);
        if (!w) {
            err << "invalid wallet file\n";
            return 1;
        }
        out << "id=" << w->id << "\n";
        return 0;
    }

    if (sub == "export") {
        std::filesystem::path in_path;
        std::filesystem::path out_path;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--in" && i + 1 < args.size()) {
                in_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (in_path.empty() || out_path.empty()) {
            err << "missing params\n";
            return 1;
        }
        const auto w = read_wallet_file(in_path);
        if (!w) {
            err << "invalid wallet file\n";
            return 1;
        }
        if (!write_wallet_file(out_path, w->id)) {
            err << "write failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    if (sub == "balance") {
        if (args.size() < 3) {
            print_usage(err);
            return 1;
        }
        const auto data_dir = std::filesystem::path(args[2]);
        std::filesystem::path wpath;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--wallet" && i + 1 < args.size()) {
                wpath = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (wpath.empty()) {
            err << "missing --wallet\n";
            return 1;
        }
        const auto w = read_wallet_file(wpath);
        if (!w) {
            err << "invalid wallet file\n";
            return 1;
        }
        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        GlobalState st(data_dir / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        const auto a = st.get_account(w->id);
        if (!a) {
            out << "0\n";
            return 0;
        }
        out << a->balance << "\n";
        return 0;
    }

    if (sub == "spv-balance") {
        if (args.size() < 3) {
            print_usage(err);
            return 1;
        }
        const auto data_dir = std::filesystem::path(args[2]);
        std::filesystem::path wpath;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--wallet" && i + 1 < args.size()) {
                wpath = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (wpath.empty()) {
            err << "missing --wallet\n";
            return 1;
        }

        const auto w = read_wallet_file(wpath);
        if (!w) {
            err << "invalid wallet file\n";
            return 1;
        }

        ChainDB::Options copt;
        copt.storage.schema_version = 1;
        ChainDB db(data_dir / "chain", copt);
        if (!db.open()) {
            err << "chain open failed\n";
            return 1;
        }
        const auto tip = db.tip();
        if (!tip) {
            err << "missing tip\n";
            return 1;
        }

        module83::LightClientVerifier v(module83::VerifierOptions{});

        {
            GlobalState::Options opt;
            opt.storage.schema_version = 1;
            GlobalState st(data_dir / "state", opt);
            if (!st.open()) {
                err << "open failed\n";
                return 1;
            }

            ValidatorStore vkeys;
            StakingLedger vstaking(StakingLedger::Options{});
            if (st.load_validator_set(vkeys, vstaking)) {
                const auto raw = st.latest_signed_checkpoint_bytes();
                if (raw) {
                    const auto cp = randio::consensus::decode_signed_checkpoint(std::span<const std::uint8_t>(raw->data(), raw->size()));
                    if (cp) {
                        const auto stv = randio::consensus::verify_signed_checkpoint(*cp, vkeys, vstaking);
                        if (stv == randio::consensus::VerifyStatus::Ok) {
                            v.set_checkpoints({randio::module82::Checkpoint{cp->header.height, cp->header.block_hash}});
                            v.set_trusted_state_root(cp->header.height, cp->header.state_root);
                        }
                    }
                }
            }
        }

        for (std::uint64_t h = 0; h <= tip->height; ++h) {
            const auto hdr = db.header_by_height(h);
            if (!hdr) {
                err << "missing header\n";
                return 1;
            }
            (void)v.add_header(*hdr);
        }

        const auto sr = db.state_root_by_height(tip->height);
        if (!sr) {
            err << "missing state root\n";
            return 1;
        }
        v.set_trusted_state_root(tip->height, *sr);

        std::ostringstream proof_out;
        std::ostringstream proof_err;
        if (run_cli({"rpc", "getAccountProof", data_dir.generic_string(), "--id", w->id}, proof_out, proof_err) != 0) {
            err << proof_err.str();
            return 1;
        }

        auto hex = proof_out.str();
        while (!hex.empty() && (hex.back() == '\n' || hex.back() == '\r' || hex.back() == ' ' || hex.back() == '\t')) {
            hex.pop_back();
        }
        while (!hex.empty() && (hex.front() == ' ' || hex.front() == '\t' || hex.front() == '\n' || hex.front() == '\r')) {
            hex.erase(hex.begin());
        }
        if (hex == "null") {
            out << "0\n";
            return 0;
        }
        if (hex.size() >= 2 && hex.front() == '"' && hex.back() == '"') {
            hex = hex.substr(1, hex.size() - 2);
        }

        const auto pb = bytes_from_hex(hex);
        if (!pb) {
            err << "bad proof hex\n";
            return 1;
        }

        module80::AccountProof p;
        std::size_t consumed = 0;
        module80::DecodeOptions popt;
        const auto st = module80::decode_account_proof(std::span<const std::uint8_t>(pb->data(), pb->size()), p, consumed, popt);
        if (st != module80::DecodeStatus::Ok || consumed != pb->size()) {
            err << "bad proof\n";
            return 1;
        }
        const auto vst = v.verify_account_proof(p);
        if (vst != module83::VerifyStatus::Ok) {
            err << "proof verify failed\n";
            return 1;
        }

        out << p.account.balance << "\n";
        return 0;
    }

    if (sub == "spv-sync") {
        if (args.size() < 3) {
            print_usage(err);
            return 1;
        }
        const auto data_dir = std::filesystem::path(args[2]);
        std::filesystem::path out_path;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) {
                out_path = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (out_path.empty()) {
            err << "missing --out\n";
            return 1;
        }

        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        GlobalState st(data_dir / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }

        ValidatorStore keys;
        StakingLedger staking(StakingLedger::Options{});
        if (!st.load_validator_set(keys, staking)) {
            err << "missing validator set\n";
            return 1;
        }
        const auto raw = st.latest_signed_checkpoint_bytes();
        if (!raw) {
            err << "missing checkpoint\n";
            return 1;
        }
        const auto cp = randio::consensus::decode_signed_checkpoint(std::span<const std::uint8_t>(raw->data(), raw->size()));
        if (!cp) {
            err << "bad checkpoint\n";
            return 1;
        }
        if (randio::consensus::verify_signed_checkpoint(*cp, keys, staking) != randio::consensus::VerifyStatus::Ok) {
            err << "checkpoint verify failed\n";
            return 1;
        }

        std::string j;
        j += "{\n";
        j += "  \"height\": " + std::to_string(cp->header.height) + ",\n";
        j += "  \"block_hash\": \"" + crypto::to_hex(cp->header.block_hash) + "\",\n";
        j += "  \"state_root\": \"" + crypto::to_hex(cp->header.state_root) + "\",\n";
        j += "  \"protocol_version\": " + std::to_string(cp->header.protocol_version) + "\n";
        j += "}\n";
        if (!write_all(out_path, j)) {
            err << "write failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    if (sub == "send") {
        if (args.size() < 3) {
            print_usage(err);
            return 1;
        }
        const auto data_dir = std::filesystem::path(args[2]);
        std::filesystem::path wpath;
        std::string to;
        std::uint64_t amount = 0;
        std::uint64_t fee = 0;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--wallet" && i + 1 < args.size()) {
                wpath = std::filesystem::path(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--to" && i + 1 < args.size()) {
                to = std::string(args[i + 1]);
                i += 1;
                continue;
            }
            if (args[i] == "--amount" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], amount)) {
                    err << "bad --amount\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            if (args[i] == "--fee" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], fee)) {
                    err << "bad --fee\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (wpath.empty() || to.empty() || amount == 0) {
            err << "missing params\n";
            return 1;
        }
        const auto w = read_wallet_file(wpath);
        if (!w) {
            err << "invalid wallet file\n";
            return 1;
        }

        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        GlobalState st(data_dir / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        const auto a = st.get_account(w->id);
        if (!a) {
            err << "missing from\n";
            return 1;
        }

        const auto tx = make_transfer_tx(w->id, to, amount, a->nonce, fee, static_cast<std::uint32_t>(st.protocol_version()));
        const auto bytes = serialize_tx(tx);
        const auto id = txid(tx);
        const auto hex = crypto::to_hex(id);

        std::error_code ec;
        const auto pool = data_dir / "txpool";
        std::filesystem::create_directories(pool, ec);
        if (ec) {
            err << "mkdir failed\n";
            return 1;
        }
        const auto out_path = pool / ("tx_" + hex + ".bin");
        std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            err << "write failed\n";
            return 1;
        }
        f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        f.flush();
        if (!f.good()) {
            err << "write failed\n";
            return 1;
        }

        out << "txid=" << hex << "\n";
        out << "queued=" << hex << "\n";
        return 0;
    }

    if (sub == "status") {
        if (args.size() != 3) {
            print_usage(err);
            return 1;
        }
        const auto data_dir = std::filesystem::path(args[2]);
        return run_cli({"rpc", "getStatus", data_dir.generic_string()}, out, err);
    }

    err << "unknown wallet subcommand\n";
    return 1;
}

[[nodiscard]] int cmd_bridge(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 3) {
        print_usage(err);
        return 1;
    }

    const auto sub = std::string(args[1]);
    const auto data_dir = std::filesystem::path(args[2]);

    std::filesystem::path out_path;
    std::filesystem::path msg_path;
    std::filesystem::path proof_path;
    std::string msg_id_hex;
    std::string wrap_action_s;

    for (std::size_t i = 3; i < args.size(); ++i) {
        if (args[i] == "--out" && i + 1 < args.size()) {
            out_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--msg" && i + 1 < args.size()) {
            msg_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--proof" && i + 1 < args.size()) {
            proof_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--msg-id" && i + 1 < args.size()) {
            msg_id_hex = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--wrap-action" && i + 1 < args.size()) {
            wrap_action_s = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        std::string j;
        j += "{\n";
        j += "  \"ok\": false,\n";
        j += "  \"err\": \"BadFormat\",\n";
        j += "  \"msg_id\": \"" + std::string(64, '0') + "\"\n";
        j += "}\n";
        if (!out_path.empty()) {
            if (!write_all(out_path, j)) {
                err << "write failed\n";
                return 1;
            }
            out << "ok\n";
            return 1;
        }
        out << j;
        return 1;
    }

    auto strip_ws_and_quotes = [](std::string s) -> std::string {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) {
            s.pop_back();
        }
        while (!s.empty() && (s.front() == '\n' || s.front() == '\r' || s.front() == ' ' || s.front() == '\t')) {
            s.erase(s.begin());
        }
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
            s = s.substr(1, s.size() - 2);
        }
        return s;
    };

    auto verify_err_name = [](const randio::bridge::module115::VerifyError e) -> std::string_view {
        using randio::bridge::module115::VerifyError;
        switch (e) {
            case VerifyError::Ok:
                return "Ok";
            case VerifyError::BadFormat:
                return "BadFormat";
            case VerifyError::BadVersion:
                return "BadVersion";
            case VerifyError::BadCheckpoint:
                return "BadCheckpoint";
            case VerifyError::BadProof:
                return "BadProof";
            case VerifyError::PayloadMismatch:
                return "PayloadMismatch";
            case VerifyError::Replay:
                return "Replay";
            case VerifyError::Overflow:
                return "Overflow";
        }
        return "BadFormat";
    };

    auto parse_hex_file = [&](const std::filesystem::path& p) -> std::optional<std::vector<std::uint8_t>> {
        const auto t = read_all(p);
        if (!t) {
            return std::nullopt;
        }
        const auto s = strip_ws_and_quotes(*t);
        return bytes_from_hex(s);
    };

    auto parse_msg_json = [&](std::string_view s) -> std::optional<randio::module115::BridgeMessageV2> {
        const auto chain_id_src = parse_json_u64_field(s, "chain_id_src");
        const auto chain_id_dst = parse_json_u64_field(s, "chain_id_dst");
        const auto nonce = parse_json_u64_field(s, "nonce");
        const auto expiry_height = parse_json_u64_field(s, "expiry_height");
        const auto amount = parse_json_u64_field(s, "amount");
        const auto token_id_hex = json_get_string(s, "token_id");
        const auto recipient_hex = json_get_string(s, "recipient");

        if (!chain_id_src || !chain_id_dst || !nonce || !expiry_height || !amount || !token_id_hex || !recipient_hex) {
            return std::nullopt;
        }

        const auto token_id = hash256_from_hex(strip_ws_and_quotes(*token_id_hex));
        const auto recipient = hash256_from_hex(strip_ws_and_quotes(*recipient_hex));
        if (!token_id || !recipient) {
            return std::nullopt;
        }

        std::vector<std::uint8_t> memo;
        if (const auto memo_hex = json_get_string(s, "memo_hex")) {
            const auto mh = bytes_from_hex(strip_ws_and_quotes(*memo_hex));
            if (!mh) {
                return std::nullopt;
            }
            memo = *mh;
        }

        randio::module115::BridgeMessageV2 m;
        m.chain_id_src = *chain_id_src;
        m.chain_id_dst = *chain_id_dst;
        m.nonce = *nonce;
        m.expiry_height = *expiry_height;
        m.payload.amount = *amount;
        m.payload.token_id = *token_id;
        m.payload.recipient = *recipient;
        m.payload.memo = std::move(memo);
        return m;
    };

    auto load_msg_file = [&](const std::filesystem::path& p) -> std::optional<randio::module115::BridgeMessageV2> {
        const auto t = read_all(p);
        if (!t) {
            return std::nullopt;
        }
        const auto sv = std::string_view(*t);
        const auto trimmed = strip_ws_and_quotes(std::string(sv));
        if (!trimmed.empty() && trimmed.front() == '{') {
            return parse_msg_json(std::string_view(trimmed));
        }
        const auto raw = bytes_from_hex(trimmed);
        if (!raw) {
            return std::nullopt;
        }
        randio::module115::DecodeOptions mopt;
        const auto msg = randio::module115::decode_message_v2(std::span<const std::uint8_t>(raw->data(), raw->size()), mopt);
        if (!msg) {
            return std::nullopt;
        }
        return *msg;
    };

    GlobalState::Options gs;
    gs.storage.schema_version = 1;
    GlobalState st(data_dir / "state", gs);
    const bool state_ok = st.open();

    auto emit_json = [&](std::string j) -> int {
        if (!out_path.empty()) {
            if (!write_all(out_path, j)) {
                err << "write failed\n";
                return 1;
            }
            out << "ok\n";
            return 0;
        }
        out << j;
        return 0;
    };

    auto emit_err = [&](const randio::bridge::module115::VerifyError e, const crypto::Hash256& id, const int rc) -> int {
        std::string j;
        j += "{\n";
        j += "  \"ok\": " + std::string(e == randio::bridge::module115::VerifyError::Ok ? "true" : "false") + ",\n";
        j += "  \"err\": \"" + std::string(verify_err_name(e)) + "\",\n";
        j += "  \"msg_id\": \"" + crypto::to_hex(id) + "\"\n";
        j += "}\n";
        (void)emit_json(j);
        return rc;
    };

    auto emit_apply = [&](const randio::bridge::module115::VerifyError e,
                          const crypto::Hash256& id,
                          const bool apply_ok,
                          const int rc) -> int {
        std::string j;
        j += "{\n";
        j += "  \"ok\": " + std::string(e == randio::bridge::module115::VerifyError::Ok ? "true" : "false") + ",\n";
        j += "  \"err\": \"" + std::string(verify_err_name(e)) + "\",\n";
        j += "  \"msg_id\": \"" + crypto::to_hex(id) + "\",\n";
        j += "  \"apply_ok\": " + std::string(apply_ok ? "true" : "false") + "\n";
        j += "}\n";
        (void)emit_json(j);
        return rc;
    };

    if (!state_ok) {
        return emit_err(randio::bridge::module115::VerifyError::BadCheckpoint, crypto::Hash256{}, 1);
    }

    if (sub == "status") {
        crypto::Hash256 id{};
        bool has_id = false;

        if (!msg_id_hex.empty()) {
            const auto h = hash256_from_hex(strip_ws_and_quotes(msg_id_hex));
            if (!h) {
                err << "bad --msg-id\n";
                return 1;
            }
            id = *h;
            has_id = true;
        } else if (!msg_path.empty()) {
            const auto msg = load_msg_file(msg_path);
            if (!msg) {
                return emit_err(randio::bridge::module115::VerifyError::BadFormat, crypto::Hash256{}, 1);
            }
            randio::module115::DecodeOptions mopt;
            const auto enc = randio::module115::encode_message_v2(*msg, mopt);
            if (!enc) {
                return emit_err(randio::bridge::module115::VerifyError::BadFormat, crypto::Hash256{}, 1);
            }
            id = randio::module115::message_id_v2(*msg, mopt);
            has_id = true;
        }

        if (!has_id) {
            return emit_err(randio::bridge::module115::VerifyError::BadFormat, crypto::Hash256{}, 1);
        }

        std::string j;
        j += "{\n";
        j += "  \"ok\": true,\n";
        j += "  \"err\": \"Ok\",\n";
        j += "  \"msg_id\": \"" + crypto::to_hex(id) + "\",\n";
        j += "  \"seen\": " + std::string(st.bridge_seen(id) ? "true" : "false") + "\n";
        j += "}\n";
        return emit_json(j);
    }

    if (sub == "mark-seen") {
        const auto h = hash256_from_hex(strip_ws_and_quotes(msg_id_hex));
        if (!h) {
            return emit_err(randio::bridge::module115::VerifyError::BadFormat, crypto::Hash256{}, 1);
        }
        StateDelta d;
        const bool ok = st.mark_bridge_seen(*h, d);
        if (!ok) {
            return emit_err(randio::bridge::module115::VerifyError::Replay, *h, 1);
        }
        return emit_err(randio::bridge::module115::VerifyError::Ok, *h, 0);
    }

    if (sub != "verify-message" && sub != "apply-wrap") {
        return emit_err(randio::bridge::module115::VerifyError::BadFormat, crypto::Hash256{}, 1);
    }

    if (msg_path.empty() || proof_path.empty()) {
        return emit_err(randio::bridge::module115::VerifyError::BadFormat, crypto::Hash256{}, 1);
    }

    const auto msg = load_msg_file(msg_path);
    if (!msg) {
        return emit_err(randio::bridge::module115::VerifyError::BadFormat, crypto::Hash256{}, 1);
    }
    const auto proof = parse_hex_file(proof_path);
    if (!proof) {
        return emit_err(randio::bridge::module115::VerifyError::BadFormat, crypto::Hash256{}, 1);
    }

    ChainDB::Options copt;
    copt.storage.schema_version = 1;
    ChainDB db(data_dir / "chain", copt);
    if (!db.open()) {
        return emit_err(randio::bridge::module115::VerifyError::BadCheckpoint, crypto::Hash256{}, 1);
    }

    randio::bridge::module115::VerifyOptions vopt;
    vopt.min_protocol_version = 1;
    vopt.max_protocol_version = 0;
    vopt.max_message_bytes = 4096;
    vopt.max_proof_bytes = 2ULL * 1024ULL * 1024ULL;
    const auto res = randio::bridge::module115::verify_message(st, db, vopt, *msg, std::span<const std::uint8_t>(proof->data(), proof->size()));

    if (sub == "verify-message") {
        return emit_err(res.err, res.msg_id, (res.err == randio::bridge::module115::VerifyError::Ok) ? 0 : 1);
    }

    if (wrap_action_s != "mint" && wrap_action_s != "burn") {
        return emit_apply(randio::bridge::module115::VerifyError::BadFormat, res.msg_id, false, 1);
    }

    if (res.err != randio::bridge::module115::VerifyError::Ok) {
        return emit_apply(res.err, res.msg_id, false, 1);
    }

    randio::module116::VerifiedWrapOp op;
    if (wrap_action_s == "mint") {
        op.action = randio::module116::WrapAction::Mint;
    } else {
        op.action = randio::module116::WrapAction::Burn;
    }
    op.asset.id = msg->payload.token_id;
    op.account = msg->payload.recipient;
    op.amount = msg->payload.amount;

    randio::StateDelta d;
    const bool apply_ok = randio::module116::apply_verified_bridge_op(st, res.msg_id, op, d);
    if (!apply_ok) {
        return emit_apply(res.err, res.msg_id, false, 1);
    }
    return emit_apply(res.err, res.msg_id, true, 0);
}

[[nodiscard]] int cmd_config_validate(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);
[[nodiscard]] int cmd_config_keys(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);
[[nodiscard]] int cmd_config_print_defaults(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);
[[nodiscard]] int cmd_config_describe(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);
[[nodiscard]] int cmd_health(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);
[[nodiscard]] int cmd_readiness(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);

[[nodiscard]] std::string build_mode_name() {
#ifdef NDEBUG
    return "Release";
#else
    return "Debug";
#endif
}

[[nodiscard]] std::string preset_name_if_any() {
    const char* v = std::getenv("CMAKE_PRESET_NAME");
    if (!v) {
        return "";
    }
    return std::string(v);
}

[[nodiscard]] bool perf_counters_compiled() {
#ifdef MOONRAND_ENABLE_PERF_COUNTERS
    return true;
#else
    return false;
#endif
}

[[nodiscard]] bool write_perf_report(const std::filesystem::path& p,
                                    const std::optional<module102::SuiteReport>& tps,
                                    const std::optional<module78::SuiteReport>& rpc,
                                    const std::optional<std::uint64_t>& node_ticks,
                                    const std::optional<std::uint64_t>& perf_cost) {
    std::string j;
    j += "{\n";
    j += "  \"build_mode\": \"" + json_escape(build_mode_name()) + "\",\n";
    j += "  \"preset\": \"" + json_escape(preset_name_if_any()) + "\",\n";
    j += "  \"perf_counters_compiled\": " + std::string(perf_counters_compiled() ? "true" : "false") + ",\n";

    if (perf_cost) {
        j += "  \"perf_cost\": " + std::to_string(*perf_cost) + ",\n";
    } else {
        j += "  \"perf_cost\": 0,\n";
    }

    if (node_ticks) {
        j += "  \"node_ticks\": " + std::to_string(*node_ticks) + ",\n";
    } else {
        j += "  \"node_ticks\": 0,\n";
    }

    if (tps) {
        std::uint64_t applied_total = 0;
        for (const auto& w : tps->workloads) {
            applied_total += w.applied_tx;
        }
        j += "  \"tps\": {\n";
        j += "    \"seed\": " + std::to_string(tps->seed) + ",\n";
        j += "    \"applied_tx_total\": " + std::to_string(applied_total) + "\n";
        j += "  },\n";
    } else {
        j += "  \"tps\": null,\n";
    }

    if (rpc) {
        std::size_t req_total = 0;
        std::size_t failed_total = 0;
        for (const auto& s : rpc->scenarios) {
            req_total += s.requests;
            failed_total += s.failed;
        }
        j += "  \"rpc\": {\n";
        j += "    \"seed\": " + std::to_string(rpc->seed) + ",\n";
        j += "    \"requests_total\": " + std::to_string(req_total) + ",\n";
        j += "    \"failed_total\": " + std::to_string(failed_total) + "\n";
        j += "  }\n";
    } else {
        j += "  \"rpc\": null\n";
    }

    j += "}\n";
    return write_all(p, j);
}

[[nodiscard]] int cmd_bench(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 3) {
        print_usage(err);
        return 1;
    }

    const auto sub = std::string(args[1]);
    const auto data_dir = std::filesystem::path(args[2]);
    const auto out_dir = data_dir / "logs";
    const auto perf_path = out_dir / "perf_report.json";

    {
        std::error_code ec;
        std::filesystem::create_directories(out_dir, ec);
        if (ec) {
            err << "mkdir failed\n";
            return 1;
        }
    }

    std::uint64_t seed = 77;
    std::uint64_t blocks = 0;
    std::string workload;

    for (std::size_t i = 3; i < args.size(); ++i) {
        if (args[i] == "--seed" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], seed)) {
                err << "bad --seed\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--blocks" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], blocks)) {
                err << "bad --blocks\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--workload" && i + 1 < args.size()) {
            workload = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (sub == "tps") {
        if (!workload.empty()) {
            const bool ok = workload == "transfer_only" || workload == "rand20_heavy" || workload == "mixed_contract_calls" || workload == "mempool_ingest_stress";
            if (!ok) {
                err << "bad --workload\n";
                return 1;
            }
        }
        module102::SuiteOptions opt;
        opt.seed = seed;
        opt.ci_mode = true;
        opt.blocks = blocks;
        opt.workload = workload;

        randio::perf::reset();
        const auto rep = module102::run_suite(opt);
        const auto cost = randio::perf::value();

        auto out_rep = rep;
        out_rep.report_path = out_dir / "tps_bench_report.json";
        if (!module102::write_report_json(out_rep)) {
            err << "write report failed\n";
            return 1;
        }
        if (!write_perf_report(perf_path, out_rep, std::nullopt, std::nullopt, cost)) {
            err << "write perf report failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    if (sub == "rpc") {
        (void)blocks;
        (void)workload;

        randio::perf::reset();
        auto rep = module78::run_suite(out_dir / "rpc_bench_tmp", seed);
        rep.report_path = out_dir / "rpc_bench_report.json";
        const auto cost = randio::perf::value();

        if (!module78::write_report_json(rep)) {
            err << "write report failed\n";
            return 1;
        }
        if (!write_perf_report(perf_path, std::nullopt, rep, std::nullopt, cost)) {
            err << "write perf report failed\n";
            return 1;
        }
        out << "ok\n";
        return 0;
    }

    if (sub == "all") {
        if (!workload.empty()) {
            const bool ok = workload == "transfer_only" || workload == "rand20_heavy" || workload == "mixed_contract_calls" || workload == "mempool_ingest_stress";
            if (!ok) {
                err << "bad --workload\n";
                return 1;
            }
        }

        randio::perf::reset();
        module102::SuiteOptions opt;
        opt.seed = seed;
        opt.ci_mode = true;
        opt.blocks = blocks;
        opt.workload = workload;
        const auto tps = module102::run_suite(opt);
        const auto cost_tps = randio::perf::value();
        auto tps_out = tps;
        tps_out.report_path = out_dir / "tps_bench_report.json";
        if (!module102::write_report_json(tps_out)) {
            err << "write report failed\n";
            return 1;
        }

        randio::perf::reset();
        auto rpc = module78::run_suite(out_dir / "rpc_bench_tmp", seed);
        rpc.report_path = out_dir / "rpc_bench_report.json";
        if (!module78::write_report_json(rpc)) {
            err << "write report failed\n";
            return 1;
        }

        const auto cost_rpc = randio::perf::value();
        const auto cost_total = cost_tps + cost_rpc;
        if (!write_perf_report(perf_path, tps_out, rpc, std::nullopt, cost_total)) {
            err << "write perf report failed\n";
            return 1;
        }

        out << "ok\n";
        return 0;
    }

    err << "unknown bench subcommand\n";
    return 1;
}

[[nodiscard]] int cmd_run_node(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }

    const auto base = std::filesystem::path(args[1]);

    const auto config_path = parse_config_path(args, err);
    cfg::Config cli_over;
    cli_over.data_dir = base;
    cli_over.node_mode = "";
    cli_over.node_id = "";
    cli_over.run_ticks = 0;

    std::string mode = "";
    std::string self_id;
    std::uint64_t ticks = 0;
    bool perf_mode = false;

    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--mode" && i + 1 < args.size()) {
            mode = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--id" && i + 1 < args.size()) {
            self_id = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--ticks" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], ticks)) {
                err << "bad --ticks\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--perf") {
            perf_mode = true;
            continue;
        }
        if (args[i] == "--config" && i + 1 < args.size()) {
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (!mode.empty()) {
        cli_over.node_mode = mode;
    }
    if (!self_id.empty()) {
        cli_over.node_id = self_id;
    }
    if (ticks != 0) {
        cli_over.run_ticks = ticks;
    }

    const auto lr = cfg::load(config_path, cli_over);
    if (!lr.errors.empty()) {
        for (const auto& [k, v] : lr.errors) {
            err << k << ": " << v << "\n";
        }
        return 1;
    }

    const auto cfg = lr.cfg;
    const auto base_dir = cfg.data_dir;
    const auto final_mode = cfg.node_mode;
    const auto final_ticks = cfg.run_ticks;

    obs::JsonlLogger logger(obs::LoggerOptions{base_dir / "logs" / "node.jsonl"});
    (void)logger.open();
    obs::Metrics metrics;

    if (perf_mode) {
        randio::perf::reset();
    }

    GlobalState::Options gs_opt;
    gs_opt.storage.schema_version = cfg.storage_schema_version;
    gs_opt.exec_cache_enabled = cfg.exec_cache_enabled;
    gs_opt.exec_cache_max_entries = static_cast<std::size_t>(cfg.exec_cache_max_entries);
    gs_opt.exec_cache_max_bytes = static_cast<std::size_t>(cfg.exec_cache_max_bytes);
    GlobalState st(base_dir / "state", gs_opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }

    ChainDB::Options copt;
    copt.storage.schema_version = cfg.storage_schema_version;
    copt.validation.max_tx_payload_bytes = 1024 * 1024;
    copt.validation.max_block_txs = 10000;
    copt.validation.max_tx_version = (std::numeric_limits<std::uint32_t>::max)();
    ChainDB db(base_dir / "chain", copt);
    if (!db.open()) {
        err << "chain open failed\n";
        return 1;
    }

    if (!db.tip().has_value()) {
        Block genesis;
        genesis.header.version = 1;
        genesis.header.height = 0;
        genesis.header.prev_block = crypto::Hash256{};
        genesis.header.timestamp_unix_seconds = 0;
        genesis.header.nonce = 0;
        genesis.transactions = {};
        genesis.header.merkle_root = merkle_root(genesis.transactions);
        if (!db.put_genesis(genesis)) {
            err << "genesis put failed\n";
            return 1;
        }
        (void)db.set_state_root(0, st.state_root());
    }

    TransactionScheduler sched(TransactionScheduler::Options{1000, 4 * 1024 * 1024});
    DeterministicExecutor ex(DeterministicExecutor::Options{1});

    const auto txpool_dir = base_dir / "txpool";

    const auto audit_path = base_dir / "logs" / "audit_trace.jsonl";
    std::uint64_t last_audit_height = 0;
    {
        std::ifstream in(audit_path, std::ios::binary);
        if (in.is_open()) {
            std::string line;
            while (std::getline(in, line)) {
                const auto h = randio::audit::extract_height(line);
                if (h && *h > last_audit_height) {
                    last_audit_height = *h;
                }
            }
        }
    }
    std::ofstream audit_out;
    {
        std::error_code ec;
        std::filesystem::create_directories(audit_path.parent_path(), ec);
        if (ec) {
            err << "mkdir failed\n";
            return 1;
        }
        audit_out.open(audit_path, std::ios::binary | std::ios::app);
        if (!audit_out.is_open()) {
            err << "audit open failed\n";
            return 1;
        }
    }

    for (std::uint64_t tick = 0; tick < final_ticks; ++tick) {
        metrics.ticks += 1;
        metrics.uptime_ticks += 1;
        if (st.halted()) {
            logger.log(obs::Level::Warn, "node", "halted", tick, db.tip() ? db.tip()->height : 0);
            out << "halted\n";
            break;
        }

        const auto tip = db.tip();
        const auto height = tip ? (tip->height + 1) : 1;
        StateDelta ud;
        (void)st.apply_scheduled_upgrade(height, ud);

        Mempool::Options mp_opt;
        mp_opt.max_tx_version = static_cast<std::uint32_t>(st.protocol_version());
        mp_opt.base_fee_per_gas = st.base_fee_per_gas();
        Mempool mp(mp_opt);

        std::vector<std::pair<crypto::Hash256, Transaction>> pool_txs;
        std::vector<Transaction> pool_raw;

        std::error_code ec;
        std::filesystem::create_directories(txpool_dir, ec);
        if (ec) {
            err << "mkdir failed\n";
            return 1;
        }

        std::vector<std::filesystem::path> entries;
        for (const auto& e : std::filesystem::directory_iterator(txpool_dir, ec)) {
            if (ec) {
                break;
            }
            if (e.is_regular_file()) {
                entries.push_back(e.path());
            }
        }
        std::sort(entries.begin(), entries.end());

        for (const auto& p : entries) {
            std::ifstream in(p, std::ios::binary);
            if (!in.is_open()) {
                continue;
            }
            std::vector<std::uint8_t> bytes;
            in.seekg(0, std::ios::end);
            const auto end = in.tellg();
            if (end < 0) {
                continue;
            }
            bytes.resize(static_cast<std::size_t>(end));
            in.seekg(0, std::ios::beg);
            in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            if (!in.good()) {
                continue;
            }
            const auto tx = parse_tx_bytes(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
            if (!tx) {
                std::filesystem::remove(p, ec);
                continue;
            }
            const auto id = txid(*tx);
            pool_txs.emplace_back(id, *tx);
            pool_raw.push_back(*tx);
            (void)mp.add(*tx);
        }

        const auto batch = sched.build_batch(mp);
        const auto plan = ExecutionPlanner::plan(batch);

        const auto state_root_before = st.state_root();
        const auto res = ex.execute(st, plan, height);

        metrics.tx_applied += static_cast<std::uint64_t>(res.applied.size());
        metrics.tx_aborted += static_cast<std::uint64_t>(res.aborted.size());

        std::vector<Transaction> applied_txs;
        for (const auto& id : res.applied) {
            for (const auto& [pid, tx] : pool_txs) {
                if (pid == id) {
                    applied_txs.push_back(tx);
                    break;
                }
            }
            std::filesystem::remove(txpool_dir / ("tx_" + crypto::to_hex(id) + ".bin"), ec);
        }
        for (const auto& id : res.aborted) {
            std::filesystem::remove(txpool_dir / ("tx_" + crypto::to_hex(id) + ".bin"), ec);
        }

        std::sort(applied_txs.begin(), applied_txs.end(), [](const Transaction& a, const Transaction& b) { return txid(a) < txid(b); });

        Block blk;
        blk.header.version = 1;
        blk.header.height = height;
        blk.header.prev_block = tip ? tip->hash : crypto::Hash256{};
        blk.header.timestamp_unix_seconds = height;
        blk.header.nonce = 0;
        blk.transactions = std::move(applied_txs);
        blk.header.merkle_root = merkle_root(blk.transactions);
        const auto bh = block_hash(blk.header);
        if (!db.add_block(blk)) {
            err << "add_block failed\n";
            return 1;
        }
        (void)db.set_state_root(height, st.state_root());

        if (height > last_audit_height) {
            randio::audit::BuildOptions bopt;
            bopt.max_keys_per_category = 200;
            bopt.include_changed_keys = true;
            const auto tr = randio::audit::from_execution(height,
                                                         blk.header.prev_block,
                                                         bh,
                                                         st.protocol_version(),
                                                         state_root_before,
                                                         st.state_root(),
                                                         res,
                                                         pool_raw,
                                                         bopt);
            randio::audit::EncodeOptions eopt;
            eopt.max_keys_per_category = bopt.max_keys_per_category;
            eopt.include_changed_keys = bopt.include_changed_keys;
            const auto line = randio::audit::encode_jsonl(tr, eopt);
            audit_out.write(line.data(), static_cast<std::streamsize>(line.size()));
            audit_out.flush();
            if (!audit_out.good()) {
                err << "audit write failed\n";
                return 1;
            }
            last_audit_height = height;
        }

        {
            ValidatorStore vkeys;
            StakingLedger vstaking(StakingLedger::Options{});
            if (st.load_validator_set(vkeys, vstaking)) {
                const auto msg = randio::consensus::encode_checkpoint_header(randio::consensus::CheckpointHeader{height, block_hash(blk.header), st.state_root(), st.protocol_version()});
                randio::consensus::SignedCheckpoint cp;
                cp.header.height = height;
                cp.header.block_hash = block_hash(blk.header);
                cp.header.state_root = st.state_root();
                cp.header.protocol_version = st.protocol_version();
                cp.signatures.clear();
                const auto ids = vkeys.ids();
                cp.signatures.reserve(ids.size());
                for (const auto& id : ids) {
                    const auto stake = vstaking.bonded_of(id);
                    if (stake == 0) {
                        continue;
                    }
                    const auto pk = vkeys.pubkey(id);
                    if (!pk) {
                        continue;
                    }
                    std::vector<std::uint8_t> buf;
                    buf.reserve(pk->size() + msg.size());
                    buf.insert(buf.end(), pk->begin(), pk->end());
                    buf.insert(buf.end(), msg.begin(), msg.end());
                    const auto sig = crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
                    cp.signatures.push_back(randio::consensus::CheckpointSig{id, sig});
                }
                StateDelta cd;
                (void)st.accept_signed_checkpoint(cp, cd);
            }
        }

        metrics.blocks_produced += 1;
        if (final_mode == "validator") {
            metrics.proposals += 1;
            metrics.votes += 1;
            if ((cfg.feature_flags & 0x4u) != 0) {
                metrics.rewards_minted += cfg.reward_per_block;
            }
        }
        logger.log(obs::Level::Info, "node", "block_committed", tick, height, {{"mode", final_mode}});

        if (final_mode == "archive") {
            (void)st.create_checkpoint();
        }
    }

    (void)metrics.write_json_file(base_dir / "logs" / "metrics.json");

    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_health(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() != 2) {
        print_usage(err);
        return 1;
    }
    const auto base = std::filesystem::path(args[1]);
    std::error_code ec;
    const bool state_ok = std::filesystem::exists(base / "state", ec);
    const bool chain_ok = std::filesystem::exists(base / "chain", ec);
    if (ec) {
        err << "fs error\n";
        return 1;
    }
    out << ((state_ok && chain_ok) ? "ok\n" : "degraded\n");
    return (state_ok && chain_ok) ? 0 : 1;
}

[[nodiscard]] int cmd_readiness(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() != 2) {
        print_usage(err);
        return 1;
    }
    const auto base = std::filesystem::path(args[1]);

    GlobalState::Options opt;
    opt.storage.schema_version = 1;
    GlobalState st(base / "state", opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }
    if (st.halted()) {
        err << "halted\n";
        return 1;
    }
    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_config_validate(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    std::optional<std::filesystem::path> p;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--config" && i + 1 < args.size()) {
            p = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }
    if (!p) {
        err << "missing --config\n";
        return 1;
    }
    const auto lr = cfg::load(p, std::nullopt);
    if (!lr.errors.empty()) {
        for (const auto& [k, v] : lr.errors) {
            err << k << ": " << v << "\n";
        }
        return 1;
    }
    out << "ok\n";
    return 0;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> bytes_from_hex(std::string_view hex);

[[nodiscard]] std::optional<crypto::Hash256> hash256_from_hex(std::string_view hex) {
    crypto::Hash256 h{};
    const auto st = randio::module72::from_hex(hex, h);
    if (st != randio::module72::DecodeStatus::Ok) {
        return std::nullopt;
    }
    return h;
}

[[nodiscard]] bool parse_u64(std::string_view s, std::uint64_t& out) {
    randio::module73::DecodeOptions opt;
    opt.require_canonical = false;
    return randio::module73::parse_u64(s, out, opt) == randio::module73::DecodeStatus::Ok;
}

[[nodiscard]] std::optional<std::pair<std::string, std::uint64_t>> parse_alloc(std::string_view s) {
    const auto pos = s.find(':');
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }
    std::string id(s.substr(0, pos));
    std::uint64_t amt = 0;
    if (!parse_u64(s.substr(pos + 1), amt)) {
        return std::nullopt;
    }
    if (id.empty()) {
        return std::nullopt;
    }
    return std::make_pair(std::move(id), amt);
}

[[nodiscard]] std::optional<econ::ScenarioKind> parse_scenario(std::string_view s) {
    using econ::ScenarioKind;
    if (s == "fee_spam") {
        return ScenarioKind::FeeSpamCongestion;
    }
    if (s == "stake_rotation") {
        return ScenarioKind::StakeRotationAbuse;
    }
    if (s == "slashing_grief") {
        return ScenarioKind::SlashingGriefing;
    }
    if (s == "cartel") {
        return ScenarioKind::ValidatorCartel;
    }
    if (s == "reward_extract") {
        return ScenarioKind::RewardExtractionFeeManipulation;
    }
    if (s == "partition") {
        return ScenarioKind::NetworkPartitionRecovery;
    }
    return std::nullopt;
}

[[nodiscard]] bool write_all(const std::filesystem::path& p, std::string_view s) {
    if (p.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
        if (ec) {
            return false;
        }
    }

    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }
    out.write(s.data(), static_cast<std::streamsize>(s.size()));
    out.flush();
    if (!out.good()) {
        return false;
    }

    out.close();
    return out.good();
}

[[nodiscard]] std::optional<std::string> read_all(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        return std::nullopt;
    }
    std::string s;
    in.seekg(0, std::ios::end);
    const auto end = in.tellg();
    if (end < 0) {
        return std::nullopt;
    }
    s.resize(static_cast<std::size_t>(end));
    in.seekg(0, std::ios::beg);
    in.read(s.data(), static_cast<std::streamsize>(s.size()));
    if (!in.good()) {
        return std::nullopt;
    }
    return s;
}

[[nodiscard]] std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\\' || c == '"') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else if (c == '\t') {
            out += "\\t";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

[[nodiscard]] std::optional<NetworkPreset> preset_for(std::string_view name) {
    if (name == "devnet") {
        return NetworkPreset{"moonrand-devnet", 0x52414E44u, 30300, 8545};
    }
    if (name == "testnet") {
        return NetworkPreset{"moonrand-testnet", 0x52414E54u, 40300, 18545};
    }
    if (name == "mainnet") {
        return NetworkPreset{"moonrand-mainnet", 0x52414E4Du, 50300, 28545};
    }
    if (name == "incentnet") {
        return NetworkPreset{"moonrand-incentnet", 0x52414E49u, 41300, 19545};
    }
    return std::nullopt;
}

[[nodiscard]] std::vector<std::pair<std::string, std::filesystem::path>> list_nodes(const std::filesystem::path& nodes_dir) {
    std::vector<std::pair<std::string, std::filesystem::path>> out;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(nodes_dir, ec)) {
        if (ec) {
            break;
        }
        if (!e.is_directory()) {
            continue;
        }
        const auto name = e.path().filename().string();
        out.emplace_back(name, e.path());
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    return out;
}

[[nodiscard]] int run_nodes_with_ticks(const std::filesystem::path& nodes_dir, const std::uint64_t ticks, std::ostream& err) {
    for (const auto& [name, nd] : list_nodes(nodes_dir)) {
        (void)name;
        const auto cfgp = nd / "config.json";
        std::ostringstream out2;
        std::ostringstream err2;
        const auto tstr = std::to_string(ticks);
        if (run_cli({"run-node", nd.generic_string(), "--config", cfgp.generic_string(), "--ticks", tstr}, out2, err2) != 0) {
            err << err2.str();
            return 1;
        }
    }
    return 0;
}

[[nodiscard]] int cmd_devnet(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    const auto sub = std::string(args[1]);
    if (sub == "init") {
        return cmd_devnet_init(args, out, err);
    }
    if (sub == "reset") {
        if (args.size() != 3) {
            print_usage(err);
            return 1;
        }
        const auto base_dir = std::filesystem::path(args[2]);
        const auto nodes_dir = base_dir / "nodes";
        std::error_code ec;
        for (const auto& [_, nd] : list_nodes(nodes_dir)) {
            std::filesystem::remove_all(nd / "state", ec);
            std::filesystem::remove_all(nd / "chain", ec);
            std::filesystem::remove_all(nd / "txpool", ec);
            std::filesystem::remove_all(nd / "logs", ec);
        }
        std::filesystem::remove_all(base_dir / "rpc", ec);
        std::filesystem::remove_all(base_dir / "explorer", ec);
        out << "ok\n";
        return 0;
    }
    if (sub == "spin-up") {
        if (args.size() < 3) {
            print_usage(err);
            return 1;
        }
        const auto base_dir = std::filesystem::path(args[2]);
        std::uint64_t ticks = 1;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--ticks" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], ticks)) {
                    err << "bad --ticks\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        const auto nodes_dir = base_dir / "nodes";
        if (run_nodes_with_ticks(nodes_dir, ticks, err) != 0) {
            return 1;
        }
        std::error_code ec;
        std::filesystem::create_directories(base_dir / "rpc", ec);
        std::filesystem::create_directories(base_dir / "explorer", ec);
        {
            std::ostringstream tmp_out;
            std::ostringstream tmp_err;
            if (run_cli({"rpc",
                         "snapshot",
                         (nodes_dir / "full1").generic_string(),
                         "--out",
                         (base_dir / "rpc" / "status.json").generic_string()},
                        tmp_out,
                        tmp_err) != 0) {
                err << tmp_err.str();
                return 1;
            }
        }
        {
            std::ostringstream tmp_out;
            std::ostringstream tmp_err;
            if (run_cli({"explorer",
                         "index",
                         (nodes_dir / "full1").generic_string(),
                         "--out",
                         (base_dir / "explorer" / "index.json").generic_string()},
                        tmp_out,
                        tmp_err) != 0) {
                err << tmp_err.str();
                return 1;
            }
        }
        out << "ok\n";
        return 0;
    }
    if (sub == "status") {
        if (args.size() != 3) {
            print_usage(err);
            return 1;
        }
        const auto base_dir = std::filesystem::path(args[2]);
        const auto nodes_dir = base_dir / "nodes";
        std::uint64_t max_height = 0;
        bool any_halted = false;
        for (const auto& [name, nd] : list_nodes(nodes_dir)) {
            ChainDB::Options copt;
            copt.storage.schema_version = 1;
            ChainDB db(nd / "chain", copt);
            if (!db.open()) {
                err << "chain open failed\n";
                return 1;
            }
            GlobalState::Options gs;
            gs.storage.schema_version = 1;
            GlobalState st(nd / "state", gs);
            if (!st.open()) {
                err << "open failed\n";
                return 1;
            }
            const auto tip = db.tip();
            const auto h = tip ? tip->height : 0;
            max_height = std::max(max_height, h);
            any_halted = any_halted || st.halted();
            out << "node=" << name << " height=" << h << " halted=" << (st.halted() ? "true" : "false") << "\n";
        }
        out << "max_height=" << max_height << " halted_any=" << (any_halted ? "true" : "false") << "\n";
        return 0;
    }
    err << "unknown devnet subcommand\n";
    return 1;
}

[[nodiscard]] std::string preset_json(std::string_view name, bool staking, bool slashing, bool rewards, std::uint64_t reward_per_block) {
    const auto p = preset_for(name);
    if (!p) {
        return "{}\n";
    }
    std::string out;
    out += "{\n";
    out += "  \"chain.id\": \"" + json_escape(p->chain_id) + "\",\n";
    out += "  \"chain.magic\": " + std::to_string(p->chain_magic) + ",\n";
    out += "  \"p2p.port\": " + std::to_string(p->p2p_port) + ",\n";
    out += "  \"rpc.port\": " + std::to_string(p->rpc_port) + ",\n";
    out += "  \"features.staking\": " + std::string(staking ? "true" : "false") + ",\n";
    out += "  \"features.slashing\": " + std::string(slashing ? "true" : "false") + ",\n";
    out += "  \"features.rewards\": " + std::string(rewards ? "true" : "false") + ",\n";
    out += "  \"rewards.per_block\": " + std::to_string(reward_per_block) + "\n";
    out += "}\n";
    return out;
}

[[nodiscard]] int cmd_testnet(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    const auto sub = std::string(args[1]);
    if (sub == "presets") {
        out << preset_json("testnet", false, false, false, 0);
        return 0;
    }
    if (sub == "init") {
        if (args.size() < 3) {
            print_usage(err);
            return 1;
        }
        const auto base_dir = std::filesystem::path(args[2]);
        std::uint64_t validators = 0;
        std::uint64_t max_supply = 0;
        std::uint64_t per_val = 0;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--validators" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], validators)) {
                    err << "bad --validators\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            if (args[i] == "--max-supply" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], max_supply)) {
                    err << "bad --max-supply\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            if (args[i] == "--balance-per-validator" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], per_val)) {
                    err << "bad --balance-per-validator\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (validators == 0 || max_supply == 0 || per_val == 0) {
            err << "missing params\n";
            return 1;
        }
        std::vector<std::pair<std::string, std::uint64_t>> alloc;
        alloc.reserve(static_cast<std::size_t>(validators) + 1);
        std::uint64_t allocated = 0;
        for (std::uint64_t i = 1; i <= validators; ++i) {
            const auto id = "v" + std::to_string(i);
            alloc.emplace_back(id, per_val);
            allocated += per_val;
        }
        if (allocated < max_supply) {
            alloc.emplace_back("faucet", max_supply - allocated);
        }
        const auto preset = preset_for("testnet");
        if (!preset) {
            err << "preset missing\n";
            return 1;
        }
        std::error_code ec;
        std::filesystem::create_directories(base_dir, ec);
        const auto gpath = base_dir / "genesis.testnet.json";
        const auto gtxt = make_genesis_json(preset->chain_id, preset->chain_magic, preset->p2p_port, preset->rpc_port, max_supply, alloc);
        if (!write_all(gpath, gtxt)) {
            err << "write failed\n";
            return 1;
        }
        (void)write_all(base_dir / "genesis.json", gtxt);
        {
            std::ostringstream tmp_out;
            if (run_cli({"genesis-freeze", gpath.generic_string()}, tmp_out, err) != 0) {
                return 1;
            }
        }
        const auto nodes_dir = base_dir / "nodes";
        std::filesystem::create_directories(nodes_dir, ec);
        for (std::uint64_t i = 1; i <= validators; ++i) {
            const auto id = "v" + std::to_string(i);
            const auto keyp = base_dir / (id + ".key.json");
            {
                std::ostringstream tmp_out;
                std::ostringstream tmp_err;
                if (run_cli({"validator-keygen", "--id", id, "--seed", "testnet", "--out", keyp.generic_string()}, tmp_out, tmp_err) != 0) {
                    err << tmp_err.str();
                    return 1;
                }
            }
            const auto vdir = nodes_dir / id;
            std::ostringstream tmp_out;
            std::ostringstream tmp_err;
            if (run_cli({"validator-onboard",
                         vdir.generic_string(),
                         "--network",
                         "testnet",
                         "--genesis",
                         gpath.generic_string(),
                         "--key",
                         keyp.generic_string(),
                         "--ticks",
                         "1"},
                        tmp_out,
                        tmp_err) != 0) {
                err << tmp_err.str();
                return 1;
            }
        }
        {
            const auto fdir = nodes_dir / "full1";
            std::ostringstream tmp_out;
            std::ostringstream tmp_err;
            if (run_cli({"node-onboard", fdir.generic_string(), "--network", "testnet", "--genesis", gpath.generic_string(), "--mode", "full", "--ticks", "1"},
                        tmp_out,
                        tmp_err) != 0) {
                err << tmp_err.str();
                return 1;
            }
        }
        {
            const auto adir = nodes_dir / "archive1";
            std::ostringstream tmp_out;
            std::ostringstream tmp_err;
            if (run_cli({"node-onboard", adir.generic_string(), "--network", "testnet", "--genesis", gpath.generic_string(), "--mode", "archive", "--ticks", "1"},
                        tmp_out,
                        tmp_err) != 0) {
                err << tmp_err.str();
                return 1;
            }
        }
        out << "ok\n";
        return 0;
    }
    if (sub == "status") {
        if (args.size() != 3) {
            print_usage(err);
            return 1;
        }
        const auto base_dir = std::filesystem::path(args[2]);
        return run_cli({"devnet", "status", base_dir.string()}, out, err);
    }
    err << "unknown testnet subcommand\n";
    return 1;
}

[[nodiscard]] int cmd_incentnet(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    const auto sub = std::string(args[1]);
    if (sub == "presets") {
        out << preset_json("incentnet", true, true, true, 1);
        return 0;
    }
    if (sub == "init") {
        if (args.size() < 3) {
            print_usage(err);
            return 1;
        }
        const auto base_dir = std::filesystem::path(args[2]);
        std::uint64_t validators = 0;
        std::uint64_t max_supply = 0;
        std::uint64_t per_val = 0;
        std::uint64_t reward_per_block = 0;
        for (std::size_t i = 3; i < args.size(); ++i) {
            if (args[i] == "--validators" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], validators)) {
                    err << "bad --validators\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            if (args[i] == "--max-supply" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], max_supply)) {
                    err << "bad --max-supply\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            if (args[i] == "--balance-per-validator" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], per_val)) {
                    err << "bad --balance-per-validator\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            if (args[i] == "--reward-per-block" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], reward_per_block)) {
                    err << "bad --reward-per-block\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (validators == 0 || max_supply == 0 || per_val == 0 || reward_per_block == 0) {
            err << "missing params\n";
            return 1;
        }
        std::vector<std::pair<std::string, std::uint64_t>> alloc;
        alloc.reserve(static_cast<std::size_t>(validators) + 1);
        std::uint64_t allocated = 0;
        for (std::uint64_t i = 1; i <= validators; ++i) {
            const auto id = "v" + std::to_string(i);
            alloc.emplace_back(id, per_val);
            allocated += per_val;
        }
        if (allocated < max_supply) {
            alloc.emplace_back("faucet", max_supply - allocated);
        }
        const auto preset = preset_for("incentnet");
        if (!preset) {
            err << "preset missing\n";
            return 1;
        }
        std::error_code ec;
        std::filesystem::create_directories(base_dir, ec);
        const auto gpath = base_dir / "genesis.incentnet.json";
        const auto gtxt = make_genesis_json(preset->chain_id, preset->chain_magic, preset->p2p_port, preset->rpc_port, max_supply, alloc);
        if (!write_all(gpath, gtxt)) {
            err << "write failed\n";
            return 1;
        }
        (void)write_all(base_dir / "genesis.json", gtxt);
        {
            std::ostringstream tmp_out;
            if (run_cli({"genesis-freeze", gpath.generic_string()}, tmp_out, err) != 0) {
                return 1;
            }
        }
        const auto nodes_dir = base_dir / "nodes";
        std::filesystem::create_directories(nodes_dir, ec);
        for (std::uint64_t i = 1; i <= validators; ++i) {
            const auto id = "v" + std::to_string(i);
            const auto keyp = base_dir / (id + ".key.json");
            {
                std::ostringstream tmp_out;
                std::ostringstream tmp_err;
                if (run_cli({"validator-keygen", "--id", id, "--seed", "incentnet", "--out", keyp.generic_string()}, tmp_out, tmp_err) != 0) {
                    err << tmp_err.str();
                    return 1;
                }
            }
            const auto vdir = nodes_dir / id;
            std::ostringstream tmp_out;
            std::ostringstream tmp_err;
            const auto rpb = std::to_string(reward_per_block);
            if (run_cli({"validator-onboard",
                         vdir.generic_string(),
                         "--network",
                         "incentnet",
                         "--genesis",
                         gpath.generic_string(),
                         "--key",
                         keyp.generic_string(),
                         "--features-staking",
                         "--features-slashing",
                         "--features-rewards",
                         "--reward-per-block",
                         rpb,
                         "--ticks",
                         "1"},
                        tmp_out,
                        tmp_err) != 0) {
                err << tmp_err.str();
                return 1;
            }
        }
        out << "ok\n";
        return 0;
    }
    if (sub == "status") {
        if (args.size() != 3) {
            print_usage(err);
            return 1;
        }
        const auto base_dir = std::filesystem::path(args[2]);
        return run_cli({"devnet", "status", base_dir.string()}, out, err);
    }
    err << "unknown incentnet subcommand\n";
    return 1;
}

[[nodiscard]] std::string make_alloc_report(const std::vector<std::pair<std::string, std::uint64_t>>& alloc) {
    std::vector<std::pair<std::string, std::uint64_t>> a = alloc;
    std::sort(a.begin(), a.end(), [](const auto& x, const auto& y) { return x.first < y.first; });
    std::string out;
    std::uint64_t total = 0;
    out += "allocations:\n";
    for (const auto& [id, amt] : a) {
        out += "  id=" + id + " amount=" + std::to_string(amt) + "\n";
        total += amt;
    }
    out += "total_allocated=" + std::to_string(total) + "\n";
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
    if (!parse_u64(s.substr(i, j - i), v)) {
        return std::nullopt;
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
        if (!parse_u64(s.substr(i, j - i), amt)) {
            return std::nullopt;
        }

        out.emplace_back(id, amt);
        pos = j;
    }
    return out;
}

[[nodiscard]] std::string make_genesis_json(std::string_view chain_id,
                                           std::uint32_t chain_magic,
                                           std::uint32_t p2p_port,
                                           std::uint32_t rpc_port,
                                           std::uint64_t max_supply,
                                           const std::vector<std::pair<std::string, std::uint64_t>>& alloc) {
    std::string out;
    out += "{\n";
    out += "  \"chain.id\": \"" + json_escape(chain_id) + "\",\n";
    out += "  \"chain.magic\": " + std::to_string(chain_magic) + ",\n";
    out += "  \"p2p.port\": " + std::to_string(p2p_port) + ",\n";
    out += "  \"rpc.port\": " + std::to_string(rpc_port) + ",\n";
    out += "  \"max_supply\": " + std::to_string(max_supply) + ",\n";
    out += "  \"protocol_version\": 1,\n";
    out += "  \"halted\": false,\n";
    out += "  \"allocations\": [\n";
    for (std::size_t i = 0; i < alloc.size(); ++i) {
        const auto& [id, amt] = alloc[i];
        out += "    {\"id\": \"" + json_escape(id) + "\", \"amount\": " + std::to_string(amt) + "}";
        out += (i + 1 == alloc.size()) ? "\n" : ",\n";
    }
    out += "  ]\n";
    out += "}\n";
    return out;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> bytes_from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }
    auto nib = [&](char c) -> std::optional<std::uint8_t> {
        if (c >= '0' && c <= '9') {
            return static_cast<std::uint8_t>(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return static_cast<std::uint8_t>(10 + (c - 'a'));
        }
        if (c >= 'A' && c <= 'F') {
            return static_cast<std::uint8_t>(10 + (c - 'A'));
        }
        return std::nullopt;
    };
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const auto hi = nib(hex[i]);
        const auto lo = nib(hex[i + 1]);
        if (!hi || !lo) {
            return std::nullopt;
        }
        out.push_back(static_cast<std::uint8_t>((*hi << 4u) | *lo));
    }
    return out;
}

[[nodiscard]] std::string bytes_to_hex(std::span<const std::uint8_t> b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.resize(b.size() * 2);
    for (std::size_t i = 0; i < b.size(); ++i) {
        s[i * 2] = kHex[(b[i] >> 4u) & 0x0Fu];
        s[i * 2 + 1] = kHex[b[i] & 0x0Fu];
    }
    return s;
}

[[nodiscard]] bool write_key_file(const std::filesystem::path& p, const ValidatorId& id, const ValidatorKeypair& kp) {
    std::string out;
    out += "{\n";
    out += "  \"id\": \"" + json_escape(id) + "\",\n";
    out += "  \"secret\": \"" + crypto::to_hex(kp.secret) + "\",\n";
    out += "  \"pubkey\": \"" + crypto::to_hex(kp.pubkey) + "\"\n";
    out += "}\n";
    return write_all(p, out);
}

[[nodiscard]] std::optional<std::string> json_get_string(std::string_view s, std::string_view key) {
    const auto k = std::string("\"") + std::string(key) + "\"";
    const auto pos = s.find(k);
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }
    const auto colon = s.find(':', pos + k.size());
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    const auto q1 = s.find('"', colon + 1);
    if (q1 == std::string_view::npos) {
        return std::nullopt;
    }
    const auto q2 = s.find('"', q1 + 1);
    if (q2 == std::string_view::npos) {
        return std::nullopt;
    }
    return std::string(s.substr(q1 + 1, q2 - (q1 + 1)));
}

[[nodiscard]] std::optional<LoadedKey> read_key_file(const std::filesystem::path& p) {
    const auto s = read_all(p);
    if (!s) {
        return std::nullopt;
    }
    const auto id = json_get_string(*s, "id");
    const auto secret_hex = json_get_string(*s, "secret");
    const auto pub_hex = json_get_string(*s, "pubkey");
    if (!id || !secret_hex || !pub_hex) {
        return std::nullopt;
    }
    const auto sec = hash256_from_hex(*secret_hex);
    const auto pub = hash256_from_hex(*pub_hex);
    if (!sec || !pub) {
        return std::nullopt;
    }
    const auto kp = ValidatorKeypair::from_secret(*sec);
    if (kp.pubkey != *pub) {
        return std::nullopt;
    }
    LoadedKey out;
    out.id = *id;
    out.kp = kp;
    return out;
}

[[nodiscard]] std::optional<Transaction> parse_tx_bytes(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 4 + 8 + 8 + 4) {
        return std::nullopt;
    }
    auto read_u32_le = [&](const std::size_t off) -> std::uint32_t {
        return static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8u) |
               (static_cast<std::uint32_t>(bytes[off + 2]) << 16u) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24u);
    };
    auto read_u64_le = [&](const std::size_t off) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= (static_cast<std::uint64_t>(bytes[off + static_cast<std::size_t>(i)]) << (8u * i));
        }
        return v;
    };

    const auto ver = read_u32_le(0);
    const auto nonce = read_u64_le(4);
    const auto fee = read_u64_le(12);
    const auto plen = read_u32_le(20);
    if (24 + static_cast<std::size_t>(plen) != bytes.size()) {
        return std::nullopt;
    }

    Transaction tx;
    tx.version = ver;
    tx.nonce = nonce;
    tx.fee = fee;
    tx.payload.assign(bytes.begin() + 24, bytes.end());
    return tx;
}

[[nodiscard]] Transaction make_transfer_tx(const std::string& from,
                                          const std::string& to,
                                          const std::uint64_t amount,
                                          const std::uint64_t expected_nonce,
                                          const std::uint64_t fee,
                                          const std::uint32_t version) {
    auto append_u64_le_local = [&](std::vector<std::uint8_t>& out, const std::uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
        }
    };

    Transaction tx;
    tx.version = version;
    tx.nonce = expected_nonce;
    tx.fee = fee;

    std::vector<std::uint8_t> p;
    p.reserve(1 + 1 + from.size() + 1 + to.size() + 8 + 8);
    p.push_back(static_cast<std::uint8_t>(0x01));
    p.push_back(static_cast<std::uint8_t>(from.size()));
    p.insert(p.end(), from.begin(), from.end());
    p.push_back(static_cast<std::uint8_t>(to.size()));
    p.insert(p.end(), to.begin(), to.end());
    append_u64_le_local(p, amount);
    append_u64_le_local(p, expected_nonce);
    tx.payload = std::move(p);
    return tx;
}

[[nodiscard]] int cmd_init_data_dir(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() != 2) {
        print_usage(err);
        return 1;
    }
    std::error_code ec;
    const auto base = std::filesystem::path(args[1]);
    std::filesystem::create_directories(base, ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    std::filesystem::create_directories(base / "state", ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    std::filesystem::create_directories(base / "chain", ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    std::filesystem::create_directories(base / "txpool", ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    std::filesystem::create_directories(base / "keys", ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    std::filesystem::create_directories(base / "logs", ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_validator_key_import(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    std::filesystem::path in_path;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--in" && i + 1 < args.size()) {
            in_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }
    if (in_path.empty()) {
        err << "missing --in\n";
        return 1;
    }
    const auto k = read_key_file(in_path);
    if (!k) {
        err << "invalid key file\n";
        return 1;
    }
    out << "id=" << k->id << "\n";
    out << "pubkey=" << crypto::to_hex(k->kp.pubkey) << "\n";
    return 0;
}

[[nodiscard]] int cmd_validator_key_export(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    std::filesystem::path in_path;
    std::filesystem::path out_path;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--in" && i + 1 < args.size()) {
            in_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--out" && i + 1 < args.size()) {
            out_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }
    if (in_path.empty() || out_path.empty()) {
        err << "missing params\n";
        return 1;
    }
    const auto k = read_key_file(in_path);
    if (!k) {
        err << "invalid key file\n";
        return 1;
    }
    if (!write_key_file(out_path, k->id, k->kp)) {
        err << "write failed\n";
        return 1;
    }
    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_state_root(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() != 2) {
        print_usage(err);
        return 1;
    }
    GlobalState::Options opt;
    opt.storage.schema_version = 1;
    GlobalState st(std::filesystem::path(args[1]) / "state", opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }
    out << crypto::to_hex(st.state_root()) << "\n";
    return 0;
}

[[nodiscard]] int cmd_checkpoint(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() != 2) {
        print_usage(err);
        return 1;
    }
    GlobalState::Options opt;
    opt.storage.schema_version = 1;
    GlobalState st(std::filesystem::path(args[1]) / "state", opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }
    if (!st.create_checkpoint()) {
        err << "checkpoint failed\n";
        return 1;
    }
    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_genesis_generate(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 5) {
        print_usage(err);
        return 1;
    }

    const auto out_json = std::filesystem::path(args[1]);

    std::uint64_t max_supply = 0;
    std::vector<std::pair<std::string, std::uint64_t>> alloc;
    std::string network = "devnet";

    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--network" && i + 1 < args.size()) {
            network = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--max-supply" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], max_supply)) {
                err << "bad --max-supply\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--alloc" && i + 1 < args.size()) {
            const auto parsed = parse_alloc(args[i + 1]);
            if (!parsed) {
                err << "bad --alloc\n";
                return 1;
            }
            alloc.push_back(*parsed);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (max_supply == 0 || alloc.empty()) {
        err << "missing params\n";
        return 1;
    }

    const auto preset = preset_for(network);
    if (!preset) {
        err << "bad --network\n";
        return 1;
    }

    const auto json = make_genesis_json(preset->chain_id, preset->chain_magic, preset->p2p_port, preset->rpc_port, max_supply, alloc);
    if (!write_all(out_json, json)) {
        err << "write failed\n";
        return 1;
    }

    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_genesis_freeze(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() != 2) {
        print_usage(err);
        return 1;
    }

    const auto p = std::filesystem::path(args[1]);
    const auto s = read_all(p);
    if (!s) {
        err << "read failed\n";
        return 1;
    }

    const auto h = crypto::sha256(std::string_view(*s));
    const auto hh = crypto::to_hex(h);

    const auto out_hash = p;
    const auto hash_path = out_hash.parent_path() / "genesis.hash";
    if (!write_all(hash_path, hh + "\n")) {
        err << "write failed\n";
        return 1;
    }

    const auto alloc = parse_genesis_allocations(*s);
    if (!alloc) {
        err << "bad genesis\n";
        return 1;
    }
    const auto report_path = out_hash.parent_path() / "allocations.report";
    if (!write_all(report_path, make_alloc_report(*alloc))) {
        err << "write failed\n";
        return 1;
    }

    out << "hash=" << hh << "\n";
    return 0;
}

[[nodiscard]] int cmd_validator_onboard(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 8) {
        print_usage(err);
        return 1;
    }
    const auto data_dir = std::filesystem::path(args[1]);
    std::filesystem::path genesis_path;
    std::filesystem::path key_path;
    std::string network;
    std::uint64_t ticks = 1;
    std::uint32_t feature_flags = 0;
    std::uint64_t reward_per_block = 0;

    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--network" && i + 1 < args.size()) {
            network = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--genesis" && i + 1 < args.size()) {
            genesis_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--key" && i + 1 < args.size()) {
            key_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--ticks" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], ticks)) {
                err << "bad --ticks\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--features-staking") {
            feature_flags |= 0x1u;
            continue;
        }
        if (args[i] == "--features-slashing") {
            feature_flags |= 0x2u;
            continue;
        }
        if (args[i] == "--features-rewards") {
            feature_flags |= 0x4u;
            continue;
        }
        if (args[i] == "--reward-per-block" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], reward_per_block)) {
                err << "bad --reward-per-block\n";
                return 1;
            }
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (network.empty() || genesis_path.empty() || key_path.empty()) {
        err << "missing params\n";
        return 1;
    }
    const auto preset = preset_for(network);
    if (!preset) {
        err << "bad --network\n";
        return 1;
    }

    {
        std::ostringstream tmp_out;
        if (run_cli({"init-data-dir", data_dir.string()}, tmp_out, err) != 0) {
            return 1;
        }
    }

    const auto gtxt = read_all(genesis_path);
    if (!gtxt) {
        err << "read failed\n";
        return 1;
    }
    const auto max_supply = parse_json_u64_field(*gtxt, "max_supply");
    if (!max_supply) {
        err << "bad genesis\n";
        return 1;
    }
    const auto alloc = parse_genesis_allocations(*gtxt);
    if (!alloc || alloc->empty()) {
        err << "bad genesis\n";
        return 1;
    }

    const auto out_genesis = data_dir / "genesis.json";
    if (!write_all(out_genesis, *gtxt)) {
        err << "write failed\n";
        return 1;
    }

    {
        std::ostringstream tmp_out;
        if (run_cli({"genesis-freeze", out_genesis.string()}, tmp_out, err) != 0) {
            return 1;
        }
    }

    const auto k = read_key_file(key_path);
    if (!k) {
        err << "invalid key file\n";
        return 1;
    }
    const auto out_key = data_dir / "keys" / "validator.json";
    if (!write_key_file(out_key, k->id, k->kp)) {
        err << "write failed\n";
        return 1;
    }

    {
        std::uint64_t total = 0;
        for (const auto& [_, amt] : *alloc) {
            total += amt;
        }

        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        opt.max_supply = *max_supply;
        GlobalState st(data_dir / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        StateDelta d;
        if (!st.init_genesis_supply(total, *alloc, d)) {
            err << "genesis init failed\n";
            return 1;
        }

        std::vector<std::pair<ValidatorId, crypto::Hash256>> pubkeys;
        std::vector<std::pair<ValidatorId, std::uint64_t>> stakes;
        for (const auto& [id, amt] : *alloc) {
            if (id.size() >= 2 && id[0] == 'v') {
                const auto sec = crypto::sha256("validator:" + id + ":" + network);
                const auto kp = ValidatorKeypair::from_secret(sec);
                pubkeys.emplace_back(id, kp.pubkey);
                stakes.emplace_back(id, amt);
            }
        }
        if (!pubkeys.empty()) {
            StateDelta vd;
            (void)st.set_validator_set(pubkeys, stakes, vd);
        }
    }

    {
        std::string cfgj;
        cfgj += "{\n";
        cfgj += "  \"data_dir\": \"" + json_escape(data_dir.generic_string()) + "\",\n";
        cfgj += "  \"chain.id\": \"" + json_escape(preset->chain_id) + "\",\n";
        cfgj += "  \"chain.magic\": " + std::to_string(preset->chain_magic) + ",\n";
        cfgj += "  \"p2p.port\": " + std::to_string(preset->p2p_port) + ",\n";
        cfgj += "  \"rpc.port\": " + std::to_string(preset->rpc_port) + ",\n";
        if (feature_flags != 0) {
            cfgj += "  \"features.staking\": " + std::string((feature_flags & 0x1u) ? "true" : "false") + ",\n";
            cfgj += "  \"features.slashing\": " + std::string((feature_flags & 0x2u) ? "true" : "false") + ",\n";
            cfgj += "  \"features.rewards\": " + std::string((feature_flags & 0x4u) ? "true" : "false") + ",\n";
            cfgj += "  \"rewards.per_block\": " + std::to_string(reward_per_block) + ",\n";
        }
        cfgj += "  \"node.mode\": \"validator\",\n";
        cfgj += "  \"node.id\": \"" + json_escape(k->id) + "\",\n";
        cfgj += "  \"node.ticks\": " + std::to_string(ticks) + "\n";
        cfgj += "}\n";
        if (!write_all(data_dir / "config.json", cfgj)) {
            err << "write failed\n";
            return 1;
        }
    }

    {
        std::ostringstream out2;
        std::ostringstream err2;
        if (run_cli({"run-node", data_dir.string(), "--config", (data_dir / "config.json").string(), "--ticks", "1"}, out2, err2) != 0) {
            err << err2.str();
            return 1;
        }
    }

    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_genesis_init(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 6) {
        print_usage(err);
        return 1;
    }

    const auto data_dir = std::filesystem::path(args[1]);

    std::uint64_t max_supply = 0;
    std::vector<std::pair<std::string, std::uint64_t>> alloc;

    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--max-supply" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], max_supply)) {
                err << "bad --max-supply\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--alloc" && i + 1 < args.size()) {
            const auto parsed = parse_alloc(args[i + 1]);
            if (!parsed) {
                err << "bad --alloc\n";
                return 1;
            }
            alloc.push_back(*parsed);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (max_supply == 0 || alloc.empty()) {
        err << "missing params\n";
        return 1;
    }

    std::uint64_t total = 0;
    for (const auto& [_, amt] : alloc) {
        const auto next = total + amt;
        if (next < total) {
            err << "supply overflow\n";
            return 1;
        }
        total = next;
    }

    GlobalState::Options opt;
    opt.storage.schema_version = 1;
    opt.max_supply = max_supply;

    GlobalState st(data_dir / "state", opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }
    StateDelta d;
    if (!st.init_genesis_supply(total, alloc, d)) {
        err << "genesis init failed\n";
        return 1;
    }

    {
        std::error_code ec;
        std::filesystem::create_directories(data_dir, ec);
        if (ec) {
            err << "mkdir failed\n";
            return 1;
        }

        std::string g;
        g += "{\n";
        g += "  \"max_supply\": " + std::to_string(max_supply) + ",\n";
        g += "  \"allocations\": [\n";
        for (std::size_t i = 0; i < alloc.size(); ++i) {
            const auto& [id, amt] = alloc[i];
            g += "    {\"id\": \"" + json_escape(id) + "\", \"amount\": " + std::to_string(amt) + "}";
            g += (i + 1 == alloc.size()) ? "\n" : ",\n";
        }
        g += "  ]\n";
        g += "}\n";
        if (!write_all(data_dir / "genesis.json", g)) {
            err << "write failed\n";
            return 1;
        }
    }

    out << "ok\n";
    return 0;
}

[[nodiscard]] int cmd_validator_keygen(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    ValidatorId id;
    std::string seed;
    std::filesystem::path out_path;

    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--id" && i + 1 < args.size()) {
            id = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--seed" && i + 1 < args.size()) {
            seed = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--out" && i + 1 < args.size()) {
            out_path = std::filesystem::path(args[i + 1]);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (id.empty() || seed.empty() || out_path.empty()) {
        err << "missing params\n";
        return 1;
    }

    const auto sec = crypto::sha256("validator:" + id + ":" + seed);
    const auto kp = ValidatorKeypair::from_secret(sec);
    if (!write_key_file(out_path, id, kp)) {
        err << "write failed\n";
        return 1;
    }

    out << "id=" << id << "\n";
    out << "pubkey=" << crypto::to_hex(kp.pubkey) << "\n";
    return 0;
}

[[nodiscard]] int cmd_tx_decode(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    std::string_view hex;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--hex" && i + 1 < args.size()) {
            hex = args[i + 1];
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }
    if (hex.empty()) {
        err << "missing --hex\n";
        return 1;
    }

    const auto bytes = bytes_from_hex(hex);
    if (!bytes) {
        err << "bad hex\n";
        return 1;
    }
    const auto tx = parse_tx_bytes(std::span<const std::uint8_t>(bytes->data(), bytes->size()));
    if (!tx) {
        err << "bad tx bytes\n";
        return 1;
    }
    const auto id = txid(*tx);

    out << "txid=" << crypto::to_hex(id) << "\n";
    out << "version=" << tx->version << "\n";
    out << "nonce=" << tx->nonce << "\n";
    out << "fee=" << tx->fee << "\n";
    out << "payload_bytes=" << tx->payload.size() << "\n";
    return 0;
}

[[nodiscard]] int cmd_tx_send(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }

    const auto data_dir = std::filesystem::path(args[1]);

    std::string_view hex;
    std::string from;
    std::string to;
    std::uint64_t amount = 0;
    std::uint64_t fee = 0;
    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--hex" && i + 1 < args.size()) {
            hex = args[i + 1];
            i += 1;
            continue;
        }
        if (args[i] == "--from" && i + 1 < args.size()) {
            from = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--to" && i + 1 < args.size()) {
            to = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--amount" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], amount)) {
                err << "bad --amount\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--fee" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], fee)) {
                err << "bad --fee\n";
                return 1;
            }
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    const bool has_hex = !hex.empty();
    const bool has_builder = (!from.empty() || !to.empty() || amount != 0 || fee != 0);
    if (has_hex && has_builder) {
        err << "conflicting args\n";
        return 1;
    }

    std::vector<std::uint8_t> bytes;
    crypto::Hash256 id{};

    if (has_hex) {
        const auto parsed = bytes_from_hex(hex);
        if (!parsed) {
            err << "bad hex\n";
            return 1;
        }
        const auto tx = parse_tx_bytes(std::span<const std::uint8_t>(parsed->data(), parsed->size()));
        if (!tx) {
            err << "bad tx bytes\n";
            return 1;
        }
        id = txid(*tx);
        bytes = *parsed;
    } else {
        if (from.empty() || to.empty() || amount == 0) {
            err << "missing params\n";
            return 1;
        }

        GlobalState::Options opt;
        opt.storage.schema_version = 1;
        GlobalState st(data_dir / "state", opt);
        if (!st.open()) {
            err << "open failed\n";
            return 1;
        }
        const auto a = st.get_account(from);
        if (!a) {
            err << "missing from\n";
            return 1;
        }

        const auto tx = make_transfer_tx(from, to, amount, a->nonce, fee, static_cast<std::uint32_t>(st.protocol_version()));
        bytes = serialize_tx(tx);
        id = txid(tx);
    }

    const auto name = crypto::to_hex(id);

    std::error_code ec;
    const auto pool = data_dir / "txpool";
    std::filesystem::create_directories(pool, ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }

    const auto out_path = pool / ("tx_" + name + ".bin");
    std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        err << "write failed\n";
        return 1;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    f.flush();
    if (!f.good()) {
        err << "write failed\n";
        return 1;
    }

    out << "queued=" << name << "\n";
    return 0;
}

[[nodiscard]] int cmd_tx_send_deploy(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    const auto data_dir = std::filesystem::path(args[1]);

    std::string from;
    std::uint64_t fee = 0;
    std::uint64_t gas = 0;
    std::string marker;
    std::string_view code_hex;

    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--from" && i + 1 < args.size()) {
            from = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--fee" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], fee)) {
                err << "bad --fee\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--gas" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], gas)) {
                err << "bad --gas\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--code-marker" && i + 1 < args.size()) {
            marker = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--code-hex" && i + 1 < args.size()) {
            code_hex = args[i + 1];
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (from.empty() || gas == 0) {
        err << "missing params\n";
        return 1;
    }
    if ((marker.empty() && code_hex.empty()) || (!marker.empty() && !code_hex.empty())) {
        err << "conflicting args\n";
        return 1;
    }

    std::vector<std::uint8_t> code;
    if (!marker.empty()) {
        if (marker != "RAND20" && marker != "RANDNFT" && marker != "STABLE118" && marker != "AMM119" && marker != "LEND119") {
            err << "bad --code-marker\n";
            return 1;
        }
        if (marker == "STABLE118") {
            code = randio::module118::stable118_marker_code();
        } else if (marker == "AMM119") {
            code = randio::module119::amm::amm119_marker_code();
        } else if (marker == "LEND119") {
            code = randio::module119::lend::lend119_marker_code();
        } else {
            code = code_marker(marker);
        }
    } else {
        const auto c = bytes_from_hex(code_hex);
        if (!c) {
            err << "bad --code-hex\n";
            return 1;
        }
        code = *c;
    }

    GlobalState::Options opt;
    opt.storage.schema_version = 1;
    GlobalState st(data_dir / "state", opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }
    const auto a = st.get_account(from);
    if (!a) {
        err << "missing from\n";
        return 1;
    }

    const auto tx = make_deploy_tx(from,
                                  a->nonce,
                                  fee,
                                  gas,
                                  std::span<const std::uint8_t>(code.data(), code.size()),
                                  static_cast<std::uint32_t>(st.protocol_version()));
    const auto bytes = serialize_tx(tx);
    const auto id = txid(tx);
    const auto name = crypto::to_hex(id);
    const auto contract = contract_address_from_deploy_txid(id);

    std::error_code ec;
    const auto pool = data_dir / "txpool";
    std::filesystem::create_directories(pool, ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    const auto out_path = pool / ("tx_" + name + ".bin");
    std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        err << "write failed\n";
        return 1;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    f.flush();
    if (!f.good()) {
        err << "write failed\n";
        return 1;
    }

    out << "contract=" << crypto::to_hex(contract) << "\n";
    out << "queued=" << name << "\n";
    return 0;
}

[[nodiscard]] int cmd_tx_send_call(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    const auto data_dir = std::filesystem::path(args[1]);

    std::string from;
    crypto::Hash256 contract{};
    bool has_contract = false;
    std::uint64_t fee = 0;
    std::uint64_t gas = 0;

    std::string_view input_hex;
    bool rand20_mint = false;
    bool rand20_transfer = false;
    bool randnft_mint = false;
    bool randnft_transfer = false;
    std::string to;
    std::uint64_t amount = 0;
    crypto::Hash256 token_id{};
    bool has_token_id = false;
    std::string meta;

    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--from" && i + 1 < args.size()) {
            from = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--contract" && i + 1 < args.size()) {
            const auto h = hash256_from_hex(args[i + 1]);
            if (!h) {
                err << "bad --contract\n";
                return 1;
            }
            contract = *h;
            has_contract = true;
            i += 1;
            continue;
        }
        if (args[i] == "--fee" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], fee)) {
                err << "bad --fee\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--gas" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], gas)) {
                err << "bad --gas\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--input-hex" && i + 1 < args.size()) {
            input_hex = args[i + 1];
            i += 1;
            continue;
        }
        if (args[i] == "--rand20-mint") {
            rand20_mint = true;
            continue;
        }
        if (args[i] == "--rand20-transfer") {
            rand20_transfer = true;
            continue;
        }
        if (args[i] == "--randnft-mint") {
            randnft_mint = true;
            continue;
        }
        if (args[i] == "--randnft-transfer") {
            randnft_transfer = true;
            continue;
        }
        if (args[i] == "--to" && i + 1 < args.size()) {
            to = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--amount" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], amount)) {
                err << "bad --amount\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--token-id" && i + 1 < args.size()) {
            const auto h = hash256_from_hex(args[i + 1]);
            if (!h) {
                err << "bad --token-id\n";
                return 1;
            }
            token_id = *h;
            has_token_id = true;
            i += 1;
            continue;
        }
        if (args[i] == "--meta" && i + 1 < args.size()) {
            meta = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (from.empty() || !has_contract || gas == 0) {
        err << "missing params\n";
        return 1;
    }

    const int mode_count = static_cast<int>(!input_hex.empty()) + static_cast<int>(rand20_mint) + static_cast<int>(rand20_transfer) +
                           static_cast<int>(randnft_mint) + static_cast<int>(randnft_transfer);
    if (mode_count != 1) {
        err << "conflicting args\n";
        return 1;
    }

    std::vector<std::uint8_t> input;
    if (!input_hex.empty()) {
        const auto b = bytes_from_hex(input_hex);
        if (!b) {
            err << "bad --input-hex\n";
            return 1;
        }
        input = *b;
    } else if (rand20_mint || rand20_transfer) {
        if (to.empty() || amount == 0) {
            err << "missing params\n";
            return 1;
        }
        input.reserve(1 + 32 + 8);
        input.push_back(static_cast<std::uint8_t>(rand20_mint ? 0x02 : 0x01));
        const auto to_addr = crypto::sha256(std::string_view(to));
        input.insert(input.end(), to_addr.begin(), to_addr.end());
        append_u64_le(input, amount);
    } else if (randnft_mint) {
        if (to.empty()) {
            err << "missing params\n";
            return 1;
        }
        const auto to_addr = crypto::sha256(std::string_view(to));
        input.reserve(1 + 32 + 4 + meta.size());
        input.push_back(static_cast<std::uint8_t>(0x01));
        input.insert(input.end(), to_addr.begin(), to_addr.end());
        append_u32_le(input, static_cast<std::uint32_t>(meta.size()));
        input.insert(input.end(), meta.begin(), meta.end());
    } else if (randnft_transfer) {
        if (to.empty() || !has_token_id) {
            err << "missing params\n";
            return 1;
        }
        const auto to_addr = crypto::sha256(std::string_view(to));
        input.reserve(1 + 32 + 32);
        input.push_back(static_cast<std::uint8_t>(0x02));
        input.insert(input.end(), token_id.begin(), token_id.end());
        input.insert(input.end(), to_addr.begin(), to_addr.end());
    }

    GlobalState::Options opt;
    opt.storage.schema_version = 1;
    GlobalState st(data_dir / "state", opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }
    const auto a = st.get_account(from);
    if (!a) {
        err << "missing from\n";
        return 1;
    }

    const auto tx = make_call_tx(from,
                                a->nonce,
                                fee,
                                contract,
                                gas,
                                std::span<const std::uint8_t>(input.data(), input.size()),
                                static_cast<std::uint32_t>(st.protocol_version()));
    const auto bytes = serialize_tx(tx);
    const auto id = txid(tx);
    const auto name = crypto::to_hex(id);

    std::error_code ec;
    const auto pool = data_dir / "txpool";
    std::filesystem::create_directories(pool, ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    const auto out_path = pool / ("tx_" + name + ".bin");
    std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        err << "write failed\n";
        return 1;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    f.flush();
    if (!f.good()) {
        err << "write failed\n";
        return 1;
    }

    out << "queued=" << name << "\n";
    return 0;
}

[[nodiscard]] int cmd_tx_send_transfer(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }
    const auto data_dir = std::filesystem::path(args[1]);

    std::string from;
    std::string to;
    std::uint64_t amount = 0;
    std::uint64_t fee = 0;

    for (std::size_t i = 2; i < args.size(); ++i) {
        if (args[i] == "--from" && i + 1 < args.size()) {
            from = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--to" && i + 1 < args.size()) {
            to = std::string(args[i + 1]);
            i += 1;
            continue;
        }
        if (args[i] == "--amount" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], amount)) {
                err << "bad --amount\n";
                return 1;
            }
            i += 1;
            continue;
        }
        if (args[i] == "--fee" && i + 1 < args.size()) {
            if (!parse_u64(args[i + 1], fee)) {
                err << "bad --fee\n";
                return 1;
            }
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    if (from.empty() || to.empty() || amount == 0) {
        err << "missing params\n";
        return 1;
    }

    GlobalState::Options opt;
    opt.storage.schema_version = 1;
    GlobalState st(data_dir / "state", opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }
    const auto a = st.get_account(from);
    if (!a) {
        err << "missing from\n";
        return 1;
    }

    const auto tx = make_transfer_tx(from, to, amount, a->nonce, fee, static_cast<std::uint32_t>(st.protocol_version()));
    const auto bytes = serialize_tx(tx);
    const auto id = txid(tx);

    std::error_code ec;
    const auto pool = data_dir / "txpool";
    std::filesystem::create_directories(pool, ec);
    if (ec) {
        err << "mkdir failed\n";
        return 1;
    }
    const auto name = crypto::to_hex(id);
    const auto out_path = pool / ("tx_" + name + ".bin");
    std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        err << "write failed\n";
        return 1;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    f.flush();
    if (!f.good()) {
        err << "write failed\n";
        return 1;
    }

    out << "queued=" << name << "\n";
    return 0;
}

[[nodiscard]] int cmd_query(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 2) {
        print_usage(err);
        return 1;
    }

    const auto sub = args[0];
    const auto data_dir = std::filesystem::path(args[1]);

    GlobalState::Options opt;
    opt.storage.schema_version = 1;
    GlobalState st(data_dir / "state", opt);
    if (!st.open()) {
        err << "open failed\n";
        return 1;
    }

    if (sub == "balance") {
        if (args.size() != 3) {
            err << "need id\n";
            return 1;
        }
        const auto a = st.get_account(args[2]);
        if (!a) {
            out << "missing\n";
            return 0;
        }
        out << a->balance << "\n";
        return 0;
    }

    if (sub == "nonce") {
        if (args.size() != 3) {
            err << "need id\n";
            return 1;
        }
        const auto a = st.get_account(args[2]);
        if (!a) {
            out << "missing\n";
            return 0;
        }
        out << a->nonce << "\n";
        return 0;
    }

    if (sub == "account") {
        if (args.size() != 3) {
            err << "need id\n";
            return 1;
        }
        const auto a = st.get_account(args[2]);
        if (!a) {
            out << "missing\n";
            return 0;
        }
        out << "balance=" << a->balance << "\n";
        out << "nonce=" << a->nonce << "\n";
        return 0;
    }

    if (sub == "supply") {
        if (args.size() != 2) {
            print_usage(err);
            return 1;
        }
        const auto m = st.minted_total();
        const auto b = st.burned_total();
        const auto c = st.circulating_supply();
        out << "minted_total=" << (m ? *m : 0) << "\n";
        out << "burned_total=" << (b ? *b : 0) << "\n";
        out << "circulating_supply=" << (c ? *c : 0) << "\n";
        return 0;
    }

    if (sub == "state-root") {
        if (args.size() != 2) {
            print_usage(err);
            return 1;
        }
        out << crypto::to_hex(st.state_root()) << "\n";
        return 0;
    }

    if (sub == "protocol-version") {
        if (args.size() != 2) {
            print_usage(err);
            return 1;
        }
        out << st.protocol_version() << "\n";
        return 0;
    }

    if (sub == "halted") {
        if (args.size() != 2) {
            print_usage(err);
            return 1;
        }
        out << (st.halted() ? "1" : "0") << "\n";
        return 0;
    }

    if (sub == "contract-address") {
        crypto::Hash256 did{};
        bool has = false;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--deploy-txid" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --deploy-txid\n";
                    return 1;
                }
                did = *h;
                has = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has) {
            err << "missing --deploy-txid\n";
            return 1;
        }
        out << crypto::to_hex(contract_address_from_deploy_txid(did)) << "\n";
        return 0;
    }

    if (sub == "contract-code") {
        crypto::Hash256 contract{};
        bool has = false;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--contract" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --contract\n";
                    return 1;
                }
                contract = *h;
                has = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has) {
            err << "missing --contract\n";
            return 1;
        }
        const auto ch = crypto::to_hex(contract);
        const auto v = st.get_contract_code(ch);
        if (!v) {
            out << "null\n";
            return 0;
        }
        out << bytes_to_hex(std::span<const std::uint8_t>(v->data(), v->size())) << "\n";
        return 0;
    }

    if (sub == "contract-storage") {
        crypto::Hash256 contract{};
        crypto::Hash256 key{};
        bool has_c = false;
        bool has_k = false;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--contract" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --contract\n";
                    return 1;
                }
                contract = *h;
                has_c = true;
                i += 1;
                continue;
            }
            if (args[i] == "--key" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --key\n";
                    return 1;
                }
                key = *h;
                has_k = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has_c || !has_k) {
            err << "missing params\n";
            return 1;
        }
        const auto v = st.get_contract_storage(crypto::to_hex(contract), key);
        if (!v) {
            out << "null\n";
            return 0;
        }
        out << bytes_to_hex(std::span<const std::uint8_t>(v->data(), v->size())) << "\n";
        return 0;
    }

    if (sub == "rand20-supply" || sub == "rand20-balance") {
        crypto::Hash256 contract{};
        bool has_c = false;
        std::string id;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--contract" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --contract\n";
                    return 1;
                }
                contract = *h;
                has_c = true;
                i += 1;
                continue;
            }
            if (args[i] == "--id" && i + 1 < args.size()) {
                id = std::string(args[i + 1]);
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has_c) {
            err << "missing --contract\n";
            return 1;
        }
        crypto::Hash256 key{};
        if (sub == "rand20-supply") {
            key = crypto::sha256("rand20:supply");
        } else {
            if (id.empty()) {
                err << "missing --id\n";
                return 1;
            }
            const auto addr = crypto::sha256(std::string_view(id));
            key = crypto::sha256("rand20:bal:" + crypto::to_hex(addr));
        }
        const auto v = st.get_contract_storage(crypto::to_hex(contract), key);
        if (!v) {
            out << "0\n";
            return 0;
        }
        const auto u = decode_u64_le(std::span<const std::uint8_t>(v->data(), v->size()));
        if (!u) {
            out << "0\n";
            return 0;
        }
        out << *u << "\n";
        return 0;
    }

    if (sub == "randnft-supply" || sub == "randnft-tokenid" || sub == "randnft-owner" || sub == "randnft-meta") {
        crypto::Hash256 contract{};
        bool has_c = false;
        crypto::Hash256 tid{};
        bool has_tid = false;
        std::uint64_t serial = 0;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--contract" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --contract\n";
                    return 1;
                }
                contract = *h;
                has_c = true;
                i += 1;
                continue;
            }
            if (args[i] == "--token-id" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --token-id\n";
                    return 1;
                }
                tid = *h;
                has_tid = true;
                i += 1;
                continue;
            }
            if (args[i] == "--serial" && i + 1 < args.size()) {
                if (!parse_u64(args[i + 1], serial)) {
                    err << "bad --serial\n";
                    return 1;
                }
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has_c) {
            err << "missing --contract\n";
            return 1;
        }
        const auto ch = crypto::to_hex(contract);

        if (sub == "randnft-supply") {
            const auto key = crypto::sha256("randnft:supply");
            const auto v = st.get_contract_storage(ch, key);
            if (!v) {
                out << "0\n";
                return 0;
            }
            const auto u = decode_u64_le(std::span<const std::uint8_t>(v->data(), v->size()));
            if (!u) {
                out << "0\n";
                return 0;
            }
            out << *u << "\n";
            return 0;
        }

        if (sub == "randnft-tokenid") {
            if (serial == 0) {
                err << "missing --serial\n";
                return 1;
            }
            out << crypto::to_hex(crypto::sha256("randnft:token:" + ch + ":" + std::to_string(serial))) << "\n";
            return 0;
        }

        if (!has_tid) {
            err << "missing --token-id\n";
            return 1;
        }

        if (sub == "randnft-owner") {
            const auto key = crypto::sha256("randnft:owner:" + crypto::to_hex(tid));
            const auto v = st.get_contract_storage(ch, key);
            if (!v || v->size() != 32) {
                out << "null\n";
                return 0;
            }
            crypto::Hash256 owner{};
            std::copy(v->begin(), v->end(), owner.begin());
            out << crypto::to_hex(owner) << "\n";
            return 0;
        }

        if (sub == "randnft-meta") {
            const auto key = crypto::sha256("randnft:meta:" + crypto::to_hex(tid));
            const auto v = st.get_contract_storage(ch, key);
            if (!v) {
                out << "null\n";
                return 0;
            }
            out << bytes_to_hex(std::span<const std::uint8_t>(v->data(), v->size())) << "\n";
            return 0;
        }
    }

    if (sub == "wrap-assets") {
        if (args.size() != 2) {
            print_usage(err);
            return 1;
        }
        const auto ids = st.wrap_registered_assets();
        for (const auto& id : ids) {
            out << crypto::to_hex(id.id) << "\n";
        }
        return 0;
    }

    if (sub == "wrap-asset") {
        crypto::Hash256 asset{};
        bool has = false;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--asset" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --asset\n";
                    return 1;
                }
                asset = *h;
                has = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has) {
            err << "missing --asset\n";
            return 1;
        }
        const auto entry = std::string("wrap:asset:") + crypto::to_hex(asset);
        const auto v = st.get_storage_entry(entry);
        if (!v) {
            out << "null\n";
            return 0;
        }
        out << std::string(v->begin(), v->end()) << "\n";
        return 0;
    }

    if (sub == "wrap-supply") {
        crypto::Hash256 asset{};
        bool has = false;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--asset" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --asset\n";
                    return 1;
                }
                asset = *h;
                has = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has) {
            err << "missing --asset\n";
            return 1;
        }
        module116::WrappedAssetId id;
        id.id = asset;
        out << "minted_total=" << st.wrap_supply_minted(id).value_or(0) << "\n";
        out << "burned_total=" << st.wrap_supply_burned(id).value_or(0) << "\n";
        out << "supply=" << st.wrap_supply(id) << "\n";
        return 0;
    }

    if (sub == "wrap-balance") {
        crypto::Hash256 asset{};
        crypto::Hash256 acct{};
        bool has_a = false;
        bool has_u = false;
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--asset" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --asset\n";
                    return 1;
                }
                asset = *h;
                has_a = true;
                i += 1;
                continue;
            }
            if (args[i] == "--account" && i + 1 < args.size()) {
                const auto h = hash256_from_hex(args[i + 1]);
                if (!h) {
                    err << "bad --account\n";
                    return 1;
                }
                acct = *h;
                has_u = true;
                i += 1;
                continue;
            }
            err << "unknown arg\n";
            return 1;
        }
        if (!has_a || !has_u) {
            err << "missing params\n";
            return 1;
        }
        module116::WrappedAssetId id;
        id.id = asset;
        const auto contract = module116::wrap116_contract_address(id);
        const auto key = module116::wrap116_balance_key(acct);
        const auto v = st.get_contract_storage(crypto::to_hex(contract), key);
        if (!v) {
            out << "0\n";
            return 0;
        }
        const auto u = decode_u64_le(std::span<const std::uint8_t>(v->data(), v->size()));
        if (!u) {
            out << "0\n";
            return 0;
        }
        out << *u << "\n";
        return 0;
    }

    err << "unknown query\n";
    return 1;
}

[[nodiscard]] int cmd_econ_sim(std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.size() < 3) {
        print_usage(err);
        return 1;
    }

    const auto out_dir = std::filesystem::path(args[1]);
    const auto scenario = parse_scenario(args[2]);
    if (!scenario) {
        err << "bad scenario\n";
        return 1;
    }

    econ::EconomicSimOptions opt;
    opt.seed = 1;
    opt.blocks = 1000;
    opt.executor.parallelism = 1;

    for (std::size_t i = 3; i < args.size(); ++i) {
        if (args[i] == "--seed" && i + 1 < args.size()) {
            std::uint64_t v = 0;
            if (!parse_u64(args[i + 1], v)) {
                err << "bad --seed\n";
                return 1;
            }
            opt.seed = v;
            i += 1;
            continue;
        }
        if (args[i] == "--blocks" && i + 1 < args.size()) {
            std::uint64_t v = 0;
            if (!parse_u64(args[i + 1], v)) {
                err << "bad --blocks\n";
                return 1;
            }
            opt.blocks = v;
            i += 1;
            continue;
        }
        err << "unknown arg\n";
        return 1;
    }

    econ::EconomicSim sim(opt);
    const auto r = sim.run(out_dir, *scenario);
    out << "transcript=" << crypto::to_hex(r.summary.transcript) << "\n";
    out << "minted_total=" << r.summary.minted_total << "\n";
    out << "burned_total=" << r.summary.burned_total << "\n";
    out << "circulating_supply=" << r.summary.circulating_supply << "\n";
    return 0;
}

}

int run(const std::span<const std::string_view> args, std::ostream& out, std::ostream& err) {
    if (args.empty()) {
        print_usage(out);
        return 1;
    }

    const auto cmd = args[0];
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage(out);
        return 0;
    }

    if (cmd == "init-data-dir") {
        return cmd_init_data_dir(args, out, err);
    }
    if (cmd == "config") {
        if (args.size() >= 2 && args[1] == "validate") {
            return cmd_config_validate(args.subspan(1), out, err);
        }
        if (args.size() >= 2 && args[1] == "keys") {
            return cmd_config_keys(args.subspan(1), out, err);
        }
        if (args.size() >= 2 && args[1] == "print-defaults") {
            return cmd_config_print_defaults(args.subspan(1), out, err);
        }
        if (args.size() >= 2 && args[1] == "describe") {
            return cmd_config_describe(args.subspan(1), out, err);
        }
        err << "unknown config subcommand\n";
        return 1;
    }
    if (cmd == "run-node") {
        return cmd_run_node(args, out, err);
    }
    if (cmd == "bench") {
        return cmd_bench(args, out, err);
    }
    if (cmd == "state-root") {
        return cmd_state_root(args, out, err);
    }
    if (cmd == "checkpoint") {
        return cmd_checkpoint(args, out, err);
    }
    if (cmd == "genesis-generate") {
        return cmd_genesis_generate(args, out, err);
    }
    if (cmd == "genesis-freeze") {
        return cmd_genesis_freeze(args, out, err);
    }
    if (cmd == "genesis-init") {
        return cmd_genesis_init(args, out, err);
    }
    if (cmd == "validator-onboard") {
        return cmd_validator_onboard(args, out, err);
    }
    if (cmd == "node-onboard") {
        return cmd_node_onboard(args, out, err);
    }
    if (cmd == "rpc") {
        return cmd_rpc_snapshot(args, out, err);
    }
    if (cmd == "explorer") {
        return cmd_explorer_index(args, out, err);
    }
    if (cmd == "devnet") {
        return cmd_devnet(args, out, err);
    }
    if (cmd == "testnet") {
        return cmd_testnet(args, out, err);
    }
    if (cmd == "incentnet") {
        return cmd_incentnet(args, out, err);
    }
    if (cmd == "validator-keygen") {
        return cmd_validator_keygen(args, out, err);
    }
    if (cmd == "validator-key-import") {
        return cmd_validator_key_import(args, out, err);
    }
    if (cmd == "validator-key-export") {
        return cmd_validator_key_export(args, out, err);
    }
    if (cmd == "wallet") {
        return cmd_wallet(args, out, err);
    }
    if (cmd == "bridge") {
        return cmd_bridge(args, out, err);
    }
    if (cmd == "oracle") {
        return cmd_oracle(args, out, err);
    }
    if (cmd == "audit") {
        return cmd_audit(args, out, err);
    }
    if (cmd == "proof") {
        return cmd_proof(args, out, err);
    }
    if (cmd == "tx") {
        if (args.size() >= 2 && args[1] == "decode") {
            return cmd_tx_decode(args.subspan(1), out, err);
        }
        if (args.size() >= 2 && args[1] == "send") {
            return cmd_tx_send(args.subspan(1), out, err);
        }
        if (args.size() >= 2 && args[1] == "send-transfer") {
            return cmd_tx_send_transfer(args.subspan(1), out, err);
        }
        if (args.size() >= 2 && args[1] == "send-deploy") {
            return cmd_tx_send_deploy(args.subspan(1), out, err);
        }
        if (args.size() >= 2 && args[1] == "send-call") {
            return cmd_tx_send_call(args.subspan(1), out, err);
        }
        err << "unknown tx subcommand\n";
        return 1;
    }
 #if MOONRAND_ENABLE_MODULE108
    if (cmd == "sol") {
        return cmd_sol(args, out, err);
    }
 #endif
    if (cmd == "query") {
        return cmd_query(args.subspan(1), out, err);
    }
    if (cmd == "admin") {
        return cmd_admin(args, out, err);
    }
    if (cmd == "econ-sim") {
        return cmd_econ_sim(args.subspan(1), out, err);
    }
    if (cmd == "health") {
        return cmd_health(args, out, err);
    }
    if (cmd == "readiness") {
        return cmd_readiness(args, out, err);
    }

    err << "unknown command\n";
    print_usage(err);
    return 1;
}

}
