#include "rand/eth/jsonrpc_shim.hpp"

#include "rand/chain_db.hpp"
#include "rand/config.hpp"
#include "rand/evm_logs.hpp"
#include "rand/hash256_codec.hpp"
#include "rand/hex.hpp"
#include "rand/state.hpp"
#include "rand/tx.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace randio::eth {
namespace {

[[nodiscard]] std::string trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())) != 0) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())) != 0) {
        s.remove_suffix(1);
    }
    return std::string(s);
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
    std::string out;
    std::size_t i = q1 + 1;
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

[[nodiscard]] std::string json_get_raw_value_or_null(std::string_view s, std::string_view key) {
    const auto k = std::string("\"") + std::string(key) + "\"";
    const auto pos = s.find(k);
    if (pos == std::string_view::npos) {
        return "null";
    }
    const auto colon = s.find(':', pos + k.size());
    if (colon == std::string_view::npos) {
        return "null";
    }
    std::size_t i = colon + 1;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])) != 0) {
        ++i;
    }
    if (i >= s.size()) {
        return "null";
    }

    if (s[i] == '"') {
        const auto q1 = i;
        ++i;
        while (i < s.size()) {
            if (s[i] == '"' && s[i - 1] != '\\') {
                const auto q2 = i;
                return std::string(s.substr(q1, (q2 - q1) + 1));
            }
            ++i;
        }
        return "null";
    }

    std::size_t j = i;
    while (j < s.size() && s[j] != ',' && s[j] != '}' && s[j] != ']') {
        ++j;
    }
    return trim(s.substr(i, j - i));
}

[[nodiscard]] std::string hex_quantity_u64(std::uint64_t v) {
    if (v == 0) {
        return "0x0";
    }
    static const char* hex = "0123456789abcdef";
    std::string out;
    while (v != 0) {
        out.push_back(hex[v & 0xFu]);
        v >>= 4u;
    }
    std::reverse(out.begin(), out.end());
    return "0x" + out;
}

[[nodiscard]] std::string hex32(const crypto::Hash256& h) {
    return std::string("0x") + crypto::to_hex(h);
}

[[nodiscard]] std::string addr20_from_id(std::string_view id) {
    const auto h = crypto::sha256(id);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(2 + 40);
    out += "0x";
    for (std::size_t i = 0; i < 20; ++i) {
        const auto b = h[i];
        out.push_back(hex[(b >> 4u) & 0xFu]);
        out.push_back(hex[b & 0xFu]);
    }
    return out;
}

[[nodiscard]] std::string addr20_from_hash256(const crypto::Hash256& h) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(2 + 40);
    out += "0x";
    for (std::size_t i = 0; i < 20; ++i) {
        const auto b = h[i];
        out.push_back(hex[(b >> 4u) & 0xFu]);
        out.push_back(hex[b & 0xFu]);
    }
    return out;
}

[[nodiscard]] std::optional<crypto::Hash256> parse_hash256_hex(std::string_view s) {
    if (s.starts_with("0x") || s.starts_with("0X")) {
        s.remove_prefix(2);
    }
    if (s.size() != 64) {
        return std::nullopt;
    }
    crypto::Hash256 out{};
    const auto st = module72::from_hex(s, out);
    if (st != module72::DecodeStatus::Ok) {
        return std::nullopt;
    }
    return out;
}

[[nodiscard]] std::optional<std::uint64_t> parse_quantity_u64(std::string_view s) {
    if (s == "latest") {
        return std::nullopt;
    }
    if (s == "earliest") {
        return 0;
    }
    if (s.starts_with("0x") || s.starts_with("0X")) {
        s.remove_prefix(2);
    }
    if (s.empty()) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (char c : s) {
        std::uint8_t nib = 0;
        if (c >= '0' && c <= '9') {
            nib = static_cast<std::uint8_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            nib = static_cast<std::uint8_t>(10 + (c - 'a'));
        } else if (c >= 'A' && c <= 'F') {
            nib = static_cast<std::uint8_t>(10 + (c - 'A'));
        } else {
            return std::nullopt;
        }
        const auto nv = (v << 4u) | nib;
        if (nv < v) {
            return std::nullopt;
        }
        v = nv;
    }
    return v;
}

[[nodiscard]] std::string jsonrpc_error(std::string_view id_raw,
                                       const int code,
                                       std::string_view msg) {
    std::string out;
    out += "{\"jsonrpc\":\"2.0\",\"id\":";
    out += std::string(id_raw);
    out += ",\"error\":{\"code\":" + std::to_string(code) + ",\"message\":\"" + json_escape(msg) + "\"}}";
    return out;
}

[[nodiscard]] std::string jsonrpc_result(std::string_view id_raw, std::string_view result_json) {
    std::string out;
    out += "{\"jsonrpc\":\"2.0\",\"id\":";
    out += std::string(id_raw);
    out += ",\"result\":";
    out += std::string(result_json);
    out += "}";
    return out;
}

[[nodiscard]] std::optional<std::string> first_param_string(std::string_view params_raw) {
    const auto b = params_raw.find('[');
    if (b == std::string_view::npos) {
        return std::nullopt;
    }
    const auto q1 = params_raw.find('"', b);
    if (q1 == std::string_view::npos) {
        return std::nullopt;
    }
    const auto q2 = params_raw.find('"', q1 + 1);
    if (q2 == std::string_view::npos) {
        return std::nullopt;
    }
    return std::string(params_raw.substr(q1 + 1, q2 - (q1 + 1)));
}

[[nodiscard]] std::optional<bool> second_param_bool(std::string_view params_raw) {
    const auto b = params_raw.find('[');
    if (b == std::string_view::npos) {
        return std::nullopt;
    }
    const auto comma = params_raw.find(',', b);
    if (comma == std::string_view::npos) {
        return std::nullopt;
    }
    auto s = params_raw.substr(comma + 1);
    s = std::string_view(trim(s));
    if (s.starts_with("true")) {
        return true;
    }
    if (s.starts_with("false")) {
        return false;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> params_raw(std::string_view req) {
    const auto k = std::string_view("\"params\"");
    const auto pos = req.find(k);
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }
    const auto colon = req.find(':', pos + k.size());
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t i = colon + 1;
    while (i < req.size() && std::isspace(static_cast<unsigned char>(req[i])) != 0) {
        ++i;
    }
    if (i >= req.size()) {
        return std::nullopt;
    }
    const char open = req[i];
    if (open != '[' && open != '{') {
        return std::nullopt;
    }
    const char close = (open == '[') ? ']' : '}';

    int depth = 0;
    bool in_str = false;
    bool esc = false;
    for (std::size_t j = i; j < req.size(); ++j) {
        const char c = req[j];
        if (in_str) {
            if (esc) {
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
            continue;
        }
        if (c == open) {
            depth += 1;
            continue;
        }
        if (c == close) {
            depth -= 1;
            if (depth == 0) {
                return std::string(req.substr(i, (j - i) + 1));
            }
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::string eth_getBlockByNumber(const ChainDB& db, const std::uint64_t h, const bool full_tx) {
    const auto b = db.block_by_height(h);
    if (!b) {
        return "null";
    }
    const auto bh = block_hash(b->header);

    std::string out;
    out += "{";
    out += "\"number\":\"" + hex_quantity_u64(b->header.height) + "\",";
    out += "\"hash\":\"" + hex32(bh) + "\",";
    out += "\"parentHash\":\"" + hex32(b->header.prev_block) + "\",";
    out += "\"transactions\":[";
    for (std::size_t i = 0; i < b->transactions.size(); ++i) {
        const auto tid = txid(b->transactions[i]);
        if (full_tx) {
            out += "{";
            out += "\"hash\":\"" + hex32(tid) + "\"";
            out += "}";
        } else {
            out += "\"" + hex32(tid) + "\"";
        }
        if (i + 1 != b->transactions.size()) {
            out += ",";
        }
    }
    out += "]";
    out += "}";
    return out;
}

[[nodiscard]] std::string eth_getTransactionByHash(const ChainDB& db, const crypto::Hash256& want) {
    const auto tip = db.tip();
    const auto maxh = tip ? tip->height : 0;

    for (std::uint64_t h = 0; h <= maxh; ++h) {
        const auto blk = db.block_by_height(h);
        if (!blk) {
            continue;
        }
        for (std::size_t i = 0; i < blk->transactions.size(); ++i) {
            const auto tid = txid(blk->transactions[i]);
            if (tid != want) {
                continue;
            }

            std::string from_id;
            if (!blk->transactions[i].payload.empty()) {
                const auto op = blk->transactions[i].payload[0];
                if (op == 0x01 || op == 0x02 || op == 0x03 || op == 0x04) {
                    if (blk->transactions[i].payload.size() >= 2) {
                        const auto n = static_cast<std::size_t>(blk->transactions[i].payload[1]);
                        if (blk->transactions[i].payload.size() >= 2 + n) {
                            from_id.assign(reinterpret_cast<const char*>(blk->transactions[i].payload.data() + 2),
                                           reinterpret_cast<const char*>(blk->transactions[i].payload.data() + 2 + n));
                        }
                    }
                }
            }
            const auto from_addr = from_id.empty() ? std::string("0x") + std::string(40, '0') : addr20_from_id(from_id);

            const auto bh = block_hash(blk->header);

            std::string out;
            out += "{";
            out += "\"hash\":\"" + hex32(tid) + "\",";
            out += "\"blockHash\":\"" + hex32(bh) + "\",";
            out += "\"blockNumber\":\"" + hex_quantity_u64(h) + "\",";
            out += "\"transactionIndex\":\"" + hex_quantity_u64(static_cast<std::uint64_t>(i)) + "\",";
            out += "\"from\":\"" + from_addr + "\"";
            out += "}";
            return out;
        }
    }

    return "null";
}

[[nodiscard]] std::string eth_getLogs(const ChainDB& db,
                                     const GlobalState& st,
                                     const std::uint64_t from_h,
                                     const std::uint64_t to_h,
                                     const std::optional<crypto::Hash256>& address,
                                     const std::array<std::optional<crypto::Hash256>, 4>& topics,
                                     const std::size_t limit) {
    const auto tip = db.tip();
    const auto maxh = tip ? tip->height : 0;
    const auto to = (to_h > maxh) ? maxh : to_h;

    if (limit == 0 || from_h > maxh || from_h > to) {
        return "[]";
    }

    module106::TopicFilter filt;
    if (address) {
        filt.address = *address;
    }
    for (int i = 0; i < 4; ++i) {
        if (topics[static_cast<std::size_t>(i)].has_value()) {
            filt.topics[static_cast<std::size_t>(i)] = std::vector<crypto::Hash256>{*topics[static_cast<std::size_t>(i)]};
        }
    }

    module106::DecodeOptions dopt;
    dopt.max_topics = 4;
    dopt.max_data_bytes = 256 * 1024;

    std::string out;
    out += "[";
    bool first = true;
    std::size_t emitted = 0;

    for (std::uint64_t h = from_h; h <= to; ++h) {
        const auto blk = db.block_by_height(h);
        if (!blk) {
            continue;
        }
        const auto bh = block_hash(blk->header);

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
                    out += ",";
                }
                first = false;

                out += "{";
                out += "\"address\":\"" + addr20_from_hash256(rec.address) + "\",";
                out += "\"blockNumber\":\"" + hex_quantity_u64(h) + "\",";
                out += "\"blockHash\":\"" + hex32(bh) + "\",";
                out += "\"transactionHash\":\"" + hex32(tid) + "\",";
                out += "\"logIndex\":\"" + hex_quantity_u64(i) + "\",";
                out += "\"topics\":[";
                for (std::size_t ti = 0; ti < rec.topics.size(); ++ti) {
                    out += "\"" + hex32(rec.topics[ti]) + "\"";
                    if (ti + 1 != rec.topics.size()) {
                        out += ",";
                    }
                }
                out += "],";
                out += "\"data\":\"0x" + module66::to_hex(std::span<const std::uint8_t>(rec.data.data(), rec.data.size())) + "\"";
                out += "}";

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

    out += "]";
    return out;
}

} // namespace

std::string handle_eth_jsonrpc(const ChainDB& db,
                              const GlobalState& st,
                              const cfg::Config& cfg,
                              const std::string_view request_body) {
    const auto id_raw = json_get_raw_value_or_null(request_body, "id");
    const auto method = json_get_string(request_body, "method");
    if (!method) {
        return jsonrpc_error(id_raw, -32600, "invalid request");
    }

    if (*method == "web3_clientVersion") {
        return jsonrpc_result(id_raw, "\"Moonrand/1\"");
    }

    if (*method == "eth_chainId") {
        return jsonrpc_result(id_raw, "\"" + hex_quantity_u64(cfg.chain_magic) + "\"");
    }

    if (*method == "eth_blockNumber") {
        const auto tip = db.tip();
        const auto h = tip ? tip->height : 0;
        return jsonrpc_result(id_raw, "\"" + hex_quantity_u64(h) + "\"");
    }

    if (*method == "eth_getBlockByNumber") {
        const auto pr = params_raw(request_body);
        if (!pr) {
            return jsonrpc_error(id_raw, -32602, "missing params");
        }
        const auto tag = first_param_string(*pr);
        if (!tag) {
            return jsonrpc_error(id_raw, -32602, "bad params");
        }
        const auto want_full = second_param_bool(*pr).value_or(false);

        const auto tip = db.tip();
        const auto maxh = tip ? tip->height : 0;
        const auto h = parse_quantity_u64(*tag).value_or(maxh);
        return jsonrpc_result(id_raw, eth_getBlockByNumber(db, h, want_full));
    }

    if (*method == "eth_getTransactionByHash") {
        const auto pr = params_raw(request_body);
        if (!pr) {
            return jsonrpc_error(id_raw, -32602, "missing params");
        }
        const auto hs = first_param_string(*pr);
        if (!hs) {
            return jsonrpc_error(id_raw, -32602, "bad params");
        }
        const auto h = parse_hash256_hex(*hs);
        if (!h) {
            return jsonrpc_error(id_raw, -32602, "bad tx hash");
        }
        return jsonrpc_result(id_raw, eth_getTransactionByHash(db, *h));
    }

    if (*method == "eth_getLogs") {
        const auto pr = params_raw(request_body);
        if (!pr) {
            return jsonrpc_error(id_raw, -32602, "missing params");
        }

        const auto fb = json_get_string(*pr, "fromBlock").value_or("0x0");
        const auto tb = json_get_string(*pr, "toBlock").value_or("latest");
        const auto from = parse_quantity_u64(fb).value_or(0);
        const auto to = parse_quantity_u64(tb);

        std::optional<crypto::Hash256> address;
        const auto addr_hex = json_get_string(*pr, "address");
        if (addr_hex) {
            address = parse_hash256_hex(*addr_hex);
        }

        std::array<std::optional<crypto::Hash256>, 4> topics;
        topics.fill(std::nullopt);
        for (int i = 0; i < 4; ++i) {
            const auto key = std::string("topic") + std::to_string(i);
            const auto th = json_get_string(*pr, key);
            if (th) {
                topics[static_cast<std::size_t>(i)] = parse_hash256_hex(*th);
            }
        }

        const std::size_t limit = 10000;

        const auto tip = db.tip();
        const auto maxh = tip ? tip->height : 0;
        const auto to_h = to.value_or(maxh);

        return jsonrpc_result(id_raw, eth_getLogs(db, st, from, to_h, address, topics, limit));
    }

    return jsonrpc_error(id_raw, -32601, "method not found");
}

}
