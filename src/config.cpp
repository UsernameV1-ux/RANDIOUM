#include "rand/config.hpp"

#include "rand/u64_codec.hpp"

#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>

namespace randio::cfg {
namespace {

[[nodiscard]] bool parse_bool(std::string_view s, bool& out) {
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

[[nodiscard]] bool parse_u64(std::string_view s, std::uint64_t& out) {
    randio::module73::DecodeOptions opt;
    opt.require_canonical = false;
    return randio::module73::parse_u64(s, out, opt) == randio::module73::DecodeStatus::Ok;
}

[[nodiscard]] bool parse_u32(std::string_view s, std::uint32_t& out) {
    std::uint64_t v = 0;
    if (!parse_u64(s, v)) {
        return false;
    }
    if (v > (std::numeric_limits<std::uint32_t>::max)()) {
        return false;
    }
    out = static_cast<std::uint32_t>(v);
    return true;
}

void skip_ws(std::string_view s, std::size_t& i) {
    while (i < s.size() && static_cast<unsigned char>(s[i]) <= 0x20) {
        ++i;
    }
}

[[nodiscard]] std::optional<std::string> parse_json_string(std::string_view s, std::size_t& i) {
    if (i >= s.size() || s[i] != '"') {
        return std::nullopt;
    }
    ++i;
    std::string out;
    while (i < s.size()) {
        const char c = s[i++];
        if (c == '"') {
            return out;
        }
        if (c == '\\') {
            if (i >= s.size()) {
                return std::nullopt;
            }
            const char e = s[i++];
            if (e == '"' || e == '\\' || e == '/') {
                out.push_back(e);
            } else if (e == 'b') {
                out.push_back('\b');
            } else if (e == 'f') {
                out.push_back('\f');
            } else if (e == 'n') {
                out.push_back('\n');
            } else if (e == 'r') {
                out.push_back('\r');
            } else if (e == 't') {
                out.push_back('\t');
            } else {
                return std::nullopt;
            }
            continue;
        }
        out.push_back(c);
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> parse_json_number_token(std::string_view s, std::size_t& i) {
    const std::size_t start = i;
    while (i < s.size() && (s[i] >= '0' && s[i] <= '9')) {
        ++i;
    }
    if (i == start) {
        return std::nullopt;
    }
    return std::string(s.substr(start, i - start));
}

[[nodiscard]] std::optional<std::string> parse_json_bool_token(std::string_view s, std::size_t& i) {
    if (s.substr(i).starts_with("true")) {
        i += 4;
        return std::string("true");
    }
    if (s.substr(i).starts_with("false")) {
        i += 5;
        return std::string("false");
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> parse_json_value_token(std::string_view s, std::size_t& i) {
    skip_ws(s, i);
    if (i >= s.size()) {
        return std::nullopt;
    }
    if (s[i] == '"') {
        return parse_json_string(s, i);
    }
    if (s[i] >= '0' && s[i] <= '9') {
        return parse_json_number_token(s, i);
    }
    if (s[i] == 't' || s[i] == 'f') {
        return parse_json_bool_token(s, i);
    }
    return std::nullopt;
}

}

Config defaults() {
    Config c;
    c.data_dir = std::filesystem::path{};
    c.chain_id = "moonrand-devnet";
    c.chain_magic = 0x52414E44u;
    c.p2p_port = 30300;
    c.rpc_port = 8545;
    c.feature_flags = 0;
    c.reward_per_block = 0;
    c.node_mode = "full";
    c.node_id = "";
    c.storage_schema_version = 1;
    c.max_tx_version = 0;
    c.exec_cache_enabled = false;
    c.exec_cache_max_entries = 100000;
    c.exec_cache_max_bytes = 64ULL * 1024ULL * 1024ULL;
    c.run_ticks = 1;
    c.log_format = "jsonl";
    return c;
}

std::vector<std::string_view> keys() {
    static constexpr std::string_view k[] = {
            "data_dir",
            "chain.id",
            "chain.magic",
            "p2p.port",
            "rpc.port",
            "features.staking",
            "features.slashing",
            "features.rewards",
            "rewards.per_block",
            "log.format",
            "node.id",
            "node.mode",
            "node.ticks",
            "storage.schema_version",
            "tx.max_version",
            "exec.cache.enabled",
            "exec.cache.max_entries",
            "exec.cache.max_bytes",
    };
    return std::vector<std::string_view>(std::begin(k), std::end(k));
}

std::optional<std::string_view> describe(const std::string_view key) {
    if (key == "data_dir") {
        return "Base data directory used by the node (contains state/, chain/, txpool/, keys/, logs/).";
    }
    if (key == "chain.id") {
        return "Chain identifier string (differs for devnet/testnet/mainnet).";
    }
    if (key == "chain.magic") {
        return "Chain network magic (uint32) used to distinguish networks.";
    }
    if (key == "p2p.port") {
        return "P2P listening port (1..65535).";
    }
    if (key == "rpc.port") {
        return "RPC listening port (1..65535).";
    }
    if (key == "features.staking") {
        return "Enable staking module (deterministic feature flag).";
    }
    if (key == "features.slashing") {
        return "Enable slashing module (requires staking).";
    }
    if (key == "features.rewards") {
        return "Enable rewards schedule (requires staking).";
    }
    if (key == "rewards.per_block") {
        return "Rewards minted per block when rewards enabled (u64, nonzero).";
    }
    if (key == "node.mode") {
        return "Node mode: validator|full|archive.";
    }
    if (key == "node.id") {
        return "Validator node ID (required when node.mode=validator).";
    }
    if (key == "node.ticks") {
        return "Deterministic tick budget for run-node (no wall clock).";
    }
    if (key == "storage.schema_version") {
        return "Disk schema version for Storage/ChainDB.";
    }
    if (key == "tx.max_version") {
        return "Maximum accepted tx version for mempool/admission (0 means default).";
    }
    if (key == "exec.cache.enabled") {
        return "Enable deterministic execution read cache (pure optimization, must not change outputs).";
    }
    if (key == "exec.cache.max_entries") {
        return "Max entries for deterministic execution caches (u64).";
    }
    if (key == "exec.cache.max_bytes") {
        return "Max bytes for deterministic execution caches (u64).";
    }
    if (key == "log.format") {
        return "Log format (jsonl only).";
    }
    return std::nullopt;
}

std::string print_defaults_json() {
    const auto d = defaults();
    std::string out;
    out += "{\n";
    out += "  \"data_dir\": \"\",\n";
    out += "  \"chain.id\": \"" + d.chain_id + "\",\n";
    out += "  \"chain.magic\": " + std::to_string(d.chain_magic) + ",\n";
    out += "  \"p2p.port\": " + std::to_string(d.p2p_port) + ",\n";
    out += "  \"rpc.port\": " + std::to_string(d.rpc_port) + ",\n";
    out += "  \"features.staking\": false,\n";
    out += "  \"features.slashing\": false,\n";
    out += "  \"features.rewards\": false,\n";
    out += "  \"rewards.per_block\": 0,\n";
    out += "  \"node.mode\": \"" + d.node_mode + "\",\n";
    out += "  \"node.id\": \"\",\n";
    out += "  \"node.ticks\": " + std::to_string(d.run_ticks) + ",\n";
    out += "  \"storage.schema_version\": " + std::to_string(d.storage_schema_version) + ",\n";
    out += "  \"tx.max_version\": " + std::to_string(d.max_tx_version) + ",\n";
    out += "  \"exec.cache.enabled\": false,\n";
    out += "  \"exec.cache.max_entries\": " + std::to_string(d.exec_cache_max_entries) + ",\n";
    out += "  \"exec.cache.max_bytes\": " + std::to_string(d.exec_cache_max_bytes) + ",\n";
    out += "  \"log.format\": \"" + d.log_format + "\"\n";
    out += "}\n";
    return out;
}

std::optional<std::string> read_file_text(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        return std::nullopt;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::optional<std::unordered_map<std::string, std::string>> parse_strict_json_object(std::string_view text) {
    std::size_t i = 0;
    skip_ws(text, i);
    if (i >= text.size() || text[i] != '{') {
        return std::nullopt;
    }
    ++i;

    std::unordered_map<std::string, std::string> out;

    for (;;) {
        skip_ws(text, i);
        if (i >= text.size()) {
            return std::nullopt;
        }
        if (text[i] == '}') {
            ++i;
            break;
        }
        const auto k = parse_json_string(text, i);
        if (!k) {
            return std::nullopt;
        }
        skip_ws(text, i);
        if (i >= text.size() || text[i] != ':') {
            return std::nullopt;
        }
        ++i;
        auto v = parse_json_value_token(text, i);
        if (!v) {
            return std::nullopt;
        }
        out.emplace(*k, *v);
        skip_ws(text, i);
        if (i >= text.size()) {
            return std::nullopt;
        }
        if (text[i] == ',') {
            ++i;
            continue;
        }
        if (text[i] == '}') {
            ++i;
            break;
        }
        return std::nullopt;
    }

    skip_ws(text, i);
    if (i != text.size()) {
        return std::nullopt;
    }

    return out;
}

LoadResult merge_and_validate(const Config& base, const std::optional<Config>& file_cfg, const std::optional<Config>& cli_overrides) {
    LoadResult r;
    r.cfg = base;

    auto apply = [&](const Config& c) {
        if (!c.data_dir.empty()) {
            r.cfg.data_dir = c.data_dir;
        }
        if (!c.chain_id.empty()) {
            r.cfg.chain_id = c.chain_id;
        }
        if (c.chain_magic != 0) {
            r.cfg.chain_magic = c.chain_magic;
        }
        if (c.p2p_port != 0) {
            r.cfg.p2p_port = c.p2p_port;
        }
        if (c.rpc_port != 0) {
            r.cfg.rpc_port = c.rpc_port;
        }
        if (c.feature_flags != 0) {
            r.cfg.feature_flags = c.feature_flags;
        }
        if (c.reward_per_block != 0) {
            r.cfg.reward_per_block = c.reward_per_block;
        }
        if (!c.node_mode.empty()) {
            r.cfg.node_mode = c.node_mode;
        }
        if (!c.node_id.empty()) {
            r.cfg.node_id = c.node_id;
        }
        if (c.storage_schema_version != 0) {
            r.cfg.storage_schema_version = c.storage_schema_version;
        }
        if (c.max_tx_version != 0) {
            r.cfg.max_tx_version = c.max_tx_version;
        }
        if (c.exec_cache_enabled) {
            r.cfg.exec_cache_enabled = c.exec_cache_enabled;
        }
        if (c.exec_cache_max_entries != 0) {
            r.cfg.exec_cache_max_entries = c.exec_cache_max_entries;
        }
        if (c.exec_cache_max_bytes != 0) {
            r.cfg.exec_cache_max_bytes = c.exec_cache_max_bytes;
        }
        if (c.run_ticks != 0) {
            r.cfg.run_ticks = c.run_ticks;
        }
        if (!c.log_format.empty()) {
            r.cfg.log_format = c.log_format;
        }
    };

    if (file_cfg) {
        apply(*file_cfg);
    }
    if (cli_overrides) {
        apply(*cli_overrides);
    }

    if (r.cfg.node_mode != "validator" && r.cfg.node_mode != "full" && r.cfg.node_mode != "archive") {
        r.errors.emplace("node.mode", "must be one of validator|full|archive");
    }
    if (r.cfg.node_mode == "validator" && r.cfg.node_id.empty()) {
        r.errors.emplace("node.id", "required when node.mode=validator");
    }
    if (r.cfg.chain_id.empty()) {
        r.errors.emplace("chain.id", "required");
    }
    if (r.cfg.chain_magic == 0) {
        r.errors.emplace("chain.magic", "must be nonzero");
    }
    if (r.cfg.exec_cache_max_entries == 0) {
        r.errors.emplace("exec.cache.max_entries", "must be nonzero");
    }
    if (r.cfg.exec_cache_max_bytes == 0) {
        r.errors.emplace("exec.cache.max_bytes", "must be nonzero");
    }
    if (r.cfg.p2p_port == 0 || r.cfg.p2p_port > 65535) {
        r.errors.emplace("p2p.port", "must be 1..65535");
    }
    if (r.cfg.rpc_port == 0 || r.cfg.rpc_port > 65535) {
        r.errors.emplace("rpc.port", "must be 1..65535");
    }
    const bool staking_enabled = (r.cfg.feature_flags & 0x1u) != 0;
    const bool slashing_enabled = (r.cfg.feature_flags & 0x2u) != 0;
    const bool rewards_enabled = (r.cfg.feature_flags & 0x4u) != 0;
    if ((slashing_enabled || rewards_enabled) && !staking_enabled) {
        r.errors.emplace("features.staking", "required when slashing/rewards enabled");
    }
    if (rewards_enabled && r.cfg.reward_per_block == 0) {
        r.errors.emplace("rewards.per_block", "required when rewards enabled");
    }
    if (r.cfg.storage_schema_version == 0) {
        r.errors.emplace("storage.schema_version", "must be >= 1");
    }
    if (r.cfg.run_ticks == 0) {
        r.errors.emplace("node.ticks", "must be >= 1");
    }
    if (r.cfg.log_format != "jsonl") {
        r.errors.emplace("log.format", "only jsonl supported");
    }

    return r;
}

LoadResult load(const std::optional<std::filesystem::path>& config_path, const std::optional<Config>& cli_overrides) {
    const auto base = defaults();

    std::optional<Config> file_cfg;
    if (config_path) {
        const auto text = read_file_text(*config_path);
        if (!text) {
            LoadResult r;
            r.cfg = base;
            r.errors.emplace("config", "cannot read config file");
            return r;
        }
        const auto kv = parse_strict_json_object(*text);
        if (!kv) {
            LoadResult r;
            r.cfg = base;
            r.errors.emplace("config", "invalid strict JSON object");
            return r;
        }

        Config c;
        for (const auto& [k, v] : *kv) {
            if (k == "data_dir") {
                c.data_dir = std::filesystem::path(v);
                continue;
            }
            if (k == "chain.id") {
                c.chain_id = v;
                continue;
            }
            if (k == "chain.magic") {
                std::uint32_t x = 0;
                if (!parse_u32(v, x)) {
                    LoadResult r;
                    r.errors.emplace("chain.magic", "must be uint32");
                    return r;
                }
                c.chain_magic = x;
                continue;
            }
            if (k == "p2p.port") {
                std::uint32_t x = 0;
                if (!parse_u32(v, x)) {
                    LoadResult r;
                    r.errors.emplace("p2p.port", "must be uint32");
                    return r;
                }
                c.p2p_port = x;
                continue;
            }
            if (k == "rpc.port") {
                std::uint32_t x = 0;
                if (!parse_u32(v, x)) {
                    LoadResult r;
                    r.errors.emplace("rpc.port", "must be uint32");
                    return r;
                }
                c.rpc_port = x;
                continue;
            }
            if (k == "features.staking") {
                bool b = false;
                if (!parse_bool(v, b)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be bool");
                    return r;
                }
                if (b) {
                    c.feature_flags |= 0x1u;
                }
                continue;
            }
            if (k == "features.slashing") {
                bool b = false;
                if (!parse_bool(v, b)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be bool");
                    return r;
                }
                if (b) {
                    c.feature_flags |= 0x2u;
                }
                continue;
            }
            if (k == "features.rewards") {
                bool b = false;
                if (!parse_bool(v, b)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be bool");
                    return r;
                }
                if (b) {
                    c.feature_flags |= 0x4u;
                }
                continue;
            }
            if (k == "rewards.per_block") {
                std::uint64_t x = 0;
                if (!parse_u64(v, x)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be u64");
                    return r;
                }
                c.reward_per_block = x;
                continue;
            }
            if (k == "node.mode") {
                c.node_mode = v;
                continue;
            }
            if (k == "node.id") {
                c.node_id = v;
                continue;
            }
            if (k == "storage.schema_version") {
                std::uint32_t x = 0;
                if (!parse_u32(v, x)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be u32");
                    return r;
                }
                c.storage_schema_version = x;
                continue;
            }
            if (k == "tx.max_version") {
                std::uint32_t x = 0;
                if (!parse_u32(v, x)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be u32");
                    return r;
                }
                c.max_tx_version = x;
                continue;
            }
            if (k == "exec.cache.enabled") {
                bool b = false;
                if (!parse_bool(v, b)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be true|false");
                    return r;
                }
                c.exec_cache_enabled = b;
                continue;
            }
            if (k == "exec.cache.max_entries") {
                std::uint64_t x = 0;
                if (!parse_u64(v, x)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be u64");
                    return r;
                }
                c.exec_cache_max_entries = x;
                continue;
            }
            if (k == "exec.cache.max_bytes") {
                std::uint64_t x = 0;
                if (!parse_u64(v, x)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be u64");
                    return r;
                }
                c.exec_cache_max_bytes = x;
                continue;
            }
            if (k == "node.ticks") {
                std::uint64_t x = 0;
                if (!parse_u64(v, x)) {
                    LoadResult r;
                    r.cfg = base;
                    r.errors.emplace(k, "must be u64");
                    return r;
                }
                c.run_ticks = x;
                continue;
            }
            if (k == "log.format") {
                c.log_format = v;
                continue;
            }
            LoadResult r;
            r.cfg = base;
            r.errors.emplace(k, "unknown key");
            return r;
        }

        file_cfg = c;
    }

    return merge_and_validate(base, file_cfg, cli_overrides);
}

}
