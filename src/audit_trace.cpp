#include "rand/audit/trace.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "rand/hash256_codec.hpp"

namespace randio::audit {
namespace {

[[nodiscard]] std::string esc(std::string_view s) {
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

[[nodiscard]] std::string to_hex(const crypto::Hash256& h) {
    return crypto::to_hex(h);
}

[[nodiscard]] std::string status_str(const TxStatus s) {
    if (s == TxStatus::Applied) {
        return "applied";
    }
    if (s == TxStatus::Aborted) {
        return "aborted";
    }
    return "rejected";
}

void append_hash_array(std::string& out, const std::vector<crypto::Hash256>& v) {
    out += "[";
    for (std::size_t i = 0; i < v.size(); ++i) {
        out += "\"" + to_hex(v[i]) + "\"";
        out += (i + 1 == v.size()) ? "" : ",";
    }
    out += "]";
}

void append_string_array(std::string& out, const std::vector<std::string>& v, const std::size_t limit) {
    out += "[";
    const auto n = (v.size() > limit) ? limit : v.size();
    for (std::size_t i = 0; i < n; ++i) {
        out += "\"" + esc(v[i]) + "\"";
        out += (i + 1 == n) ? "" : ",";
    }
    out += "]";
}

void skip_ws(std::string_view s, std::size_t& i) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) {
        ++i;
    }
}

[[nodiscard]] bool eat(std::string_view s, std::size_t& i, const char c) {
    skip_ws(s, i);
    if (i >= s.size() || s[i] != c) {
        return false;
    }
    ++i;
    return true;
}

[[nodiscard]] std::optional<std::string> parse_json_string(std::string_view s, std::size_t& i) {
    skip_ws(s, i);
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

[[nodiscard]] std::optional<std::uint64_t> parse_u64(std::string_view s, std::size_t& i) {
    skip_ws(s, i);
    if (i >= s.size()) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    bool any = false;
    while (i < s.size()) {
        const char c = s[i];
        if (c < '0' || c > '9') {
            break;
        }
        any = true;
        const auto d = static_cast<std::uint64_t>(c - '0');
        const auto next = v * 10 + d;
        if (next < v) {
            return std::nullopt;
        }
        v = next;
        ++i;
    }
    if (!any) {
        return std::nullopt;
    }
    return v;
}

[[nodiscard]] std::optional<crypto::Hash256> parse_hash_hex(std::string_view s, std::size_t& i) {
    const auto hx = parse_json_string(s, i);
    if (!hx) {
        return std::nullopt;
    }
    return randio::module72::from_hex(*hx);
}

[[nodiscard]] std::optional<std::vector<crypto::Hash256>> parse_hash_array(std::string_view s, std::size_t& i) {
    if (!eat(s, i, '[')) {
        return std::nullopt;
    }
    std::vector<crypto::Hash256> out;
    skip_ws(s, i);
    if (i < s.size() && s[i] == ']') {
        ++i;
        return out;
    }
    while (i < s.size()) {
        const auto h = parse_hash_hex(s, i);
        if (!h) {
            return std::nullopt;
        }
        out.push_back(*h);
        skip_ws(s, i);
        if (i >= s.size()) {
            return std::nullopt;
        }
        if (s[i] == ',') {
            ++i;
            continue;
        }
        if (s[i] == ']') {
            ++i;
            return out;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::vector<std::string>> parse_string_array(std::string_view s, std::size_t& i) {
    if (!eat(s, i, '[')) {
        return std::nullopt;
    }
    std::vector<std::string> out;
    skip_ws(s, i);
    if (i < s.size() && s[i] == ']') {
        ++i;
        return out;
    }
    while (i < s.size()) {
        const auto str = parse_json_string(s, i);
        if (!str) {
            return std::nullopt;
        }
        out.push_back(*str);
        skip_ws(s, i);
        if (i >= s.size()) {
            return std::nullopt;
        }
        if (s[i] == ',') {
            ++i;
            continue;
        }
        if (s[i] == ']') {
            ++i;
            return out;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<TxStatus> parse_status(std::string_view s) {
    if (s == "applied") {
        return TxStatus::Applied;
    }
    if (s == "aborted") {
        return TxStatus::Aborted;
    }
    if (s == "rejected") {
        return TxStatus::Rejected;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::vector<TxResult>> parse_tx_results(std::string_view s, std::size_t& i) {
    if (!eat(s, i, '[')) {
        return std::nullopt;
    }
    std::vector<TxResult> out;
    skip_ws(s, i);
    if (i < s.size() && s[i] == ']') {
        ++i;
        return out;
    }
    while (i < s.size()) {
        if (!eat(s, i, '{')) {
            return std::nullopt;
        }

        auto key = parse_json_string(s, i);
        if (!key || *key != "txid") {
            return std::nullopt;
        }
        if (!eat(s, i, ':')) {
            return std::nullopt;
        }
        const auto txid = parse_hash_hex(s, i);
        if (!txid) {
            return std::nullopt;
        }
        if (!eat(s, i, ',')) {
            return std::nullopt;
        }

        key = parse_json_string(s, i);
        if (!key || *key != "status") {
            return std::nullopt;
        }
        if (!eat(s, i, ':')) {
            return std::nullopt;
        }
        const auto status_s = parse_json_string(s, i);
        if (!status_s) {
            return std::nullopt;
        }
        const auto st = parse_status(*status_s);
        if (!st) {
            return std::nullopt;
        }
        if (!eat(s, i, ',')) {
            return std::nullopt;
        }

        key = parse_json_string(s, i);
        if (!key || *key != "reason_code") {
            return std::nullopt;
        }
        if (!eat(s, i, ':')) {
            return std::nullopt;
        }
        const auto rc_u = parse_u64(s, i);
        if (!rc_u || *rc_u > 255) {
            return std::nullopt;
        }
        const auto rc = static_cast<ReasonCode>(static_cast<std::uint8_t>(*rc_u));
        if (!eat(s, i, ',')) {
            return std::nullopt;
        }

        key = parse_json_string(s, i);
        if (!key || *key != "fee_charged") {
            return std::nullopt;
        }
        if (!eat(s, i, ':')) {
            return std::nullopt;
        }
        const auto fee = parse_u64(s, i);
        if (!fee) {
            return std::nullopt;
        }
        if (!eat(s, i, ',')) {
            return std::nullopt;
        }

        key = parse_json_string(s, i);
        if (!key || *key != "gas_used") {
            return std::nullopt;
        }
        if (!eat(s, i, ':')) {
            return std::nullopt;
        }
        const auto gas = parse_u64(s, i);
        if (!gas) {
            return std::nullopt;
        }
        if (!eat(s, i, ',')) {
            return std::nullopt;
        }

        key = parse_json_string(s, i);
        if (!key || *key != "tx_hex") {
            return std::nullopt;
        }
        if (!eat(s, i, ':')) {
            return std::nullopt;
        }
        const auto tx_hex = parse_json_string(s, i);
        if (!tx_hex) {
            return std::nullopt;
        }

        if (!eat(s, i, '}')) {
            return std::nullopt;
        }

        TxResult tr;
        tr.txid = *txid;
        tr.status = *st;
        tr.reason = rc;
        tr.fee_charged = *fee;
        tr.gas_used = *gas;
        tr.tx_hex = *tx_hex;
        out.push_back(std::move(tr));

        skip_ws(s, i);
        if (i >= s.size()) {
            return std::nullopt;
        }
        if (s[i] == ',') {
            ++i;
            continue;
        }
        if (s[i] == ']') {
            ++i;
            return out;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

}

std::string encode_jsonl(const BlockTrace& t, const EncodeOptions& opt) {
    std::string out;
    out.reserve(1024);

    out += "{";
    out += "\"schema\":" + std::to_string(kTraceSchemaVersion);
    out += ",\"height\":" + std::to_string(t.height);
    out += ",\"block_hash\":\"" + to_hex(t.block_hash) + "\"";
    out += ",\"prev_hash\":\"" + to_hex(t.prev_hash) + "\"";
    out += ",\"protocol_version\":" + std::to_string(t.protocol_version);
    out += ",\"state_root_before\":\"" + to_hex(t.state_root_before) + "\"";
    out += ",\"state_root_after\":\"" + to_hex(t.state_root_after) + "\"";

    out += ",\"applied_txids\":";
    append_hash_array(out, t.applied_txids);

    out += ",\"tx_results\":[";
    for (std::size_t i = 0; i < t.tx_results.size(); ++i) {
        const auto& r = t.tx_results[i];
        out += "{";
        out += "\"txid\":\"" + to_hex(r.txid) + "\"";
        out += ",\"status\":\"" + status_str(r.status) + "\"";
        out += ",\"reason_code\":" + std::to_string(static_cast<std::uint64_t>(r.reason));
        out += ",\"fee_charged\":" + std::to_string(r.fee_charged);
        out += ",\"gas_used\":" + std::to_string(r.gas_used);
        out += ",\"tx_hex\":\"" + esc(r.tx_hex) + "\"";
        out += "}";
        out += (i + 1 == t.tx_results.size()) ? "" : ",";
    }
    out += "]";

    out += ",\"state_delta_summary\":{";
    out += "\"accounts\":" + std::to_string(t.delta.accounts);
    out += ",\"codes\":" + std::to_string(t.delta.codes);
    out += ",\"storage\":" + std::to_string(t.delta.storage);
    out += ",\"meta\":" + std::to_string(t.delta.meta);

    if (opt.include_changed_keys) {
        if (!t.delta.account_keys.empty()) {
            out += ",\"account_keys\":";
            append_string_array(out, t.delta.account_keys, opt.max_keys_per_category);
        }
        if (!t.delta.code_keys.empty()) {
            out += ",\"code_keys\":";
            append_string_array(out, t.delta.code_keys, opt.max_keys_per_category);
        }
        if (!t.delta.storage_keys.empty()) {
            out += ",\"storage_keys\":";
            append_string_array(out, t.delta.storage_keys, opt.max_keys_per_category);
        }
        if (!t.delta.meta_keys.empty()) {
            out += ",\"meta_keys\":";
            append_string_array(out, t.delta.meta_keys, opt.max_keys_per_category);
        }
    }

    out += "}";

    out += "}\n";
    return out;
}

std::optional<std::uint64_t> extract_height(const std::string_view json_line) {
    const auto key = std::string_view("\"height\":");
    const auto pos = json_line.find(key);
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t i = pos + key.size();
    while (i < json_line.size() && (json_line[i] == ' ' || json_line[i] == '\t')) {
        ++i;
    }
    if (i >= json_line.size()) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    bool any = false;
    while (i < json_line.size()) {
        const char c = json_line[i];
        if (c < '0' || c > '9') {
            break;
        }
        any = true;
        const auto d = static_cast<std::uint64_t>(c - '0');
        const auto next = v * 10 + d;
        if (next < v) {
            return std::nullopt;
        }
        v = next;
        ++i;
    }
    if (!any) {
        return std::nullopt;
    }
    return v;
}

std::optional<BlockTrace> decode_jsonl(const std::string_view json_line) {
    std::size_t i = 0;
    if (!eat(json_line, i, '{')) {
        return std::nullopt;
    }

    auto key = parse_json_string(json_line, i);
    if (!key || *key != "schema") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto schema = parse_u64(json_line, i);
    if (!schema || *schema != kTraceSchemaVersion) {
        return std::nullopt;
    }
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "height") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto height = parse_u64(json_line, i);
    if (!height) {
        return std::nullopt;
    }
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "block_hash") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto block_hash = parse_hash_hex(json_line, i);
    if (!block_hash) {
        return std::nullopt;
    }
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "prev_hash") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto prev_hash = parse_hash_hex(json_line, i);
    if (!prev_hash) {
        return std::nullopt;
    }
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "protocol_version") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto pv = parse_u64(json_line, i);
    if (!pv || *pv > 65535) {
        return std::nullopt;
    }
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "state_root_before") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto state_root_before = parse_hash_hex(json_line, i);
    if (!state_root_before) {
        return std::nullopt;
    }
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "state_root_after") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto state_root_after = parse_hash_hex(json_line, i);
    if (!state_root_after) {
        return std::nullopt;
    }
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "applied_txids") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto applied_txids = parse_hash_array(json_line, i);
    if (!applied_txids) {
        return std::nullopt;
    }
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "tx_results") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto tx_results = parse_tx_results(json_line, i);
    if (!tx_results) {
        return std::nullopt;
    }
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "state_delta_summary") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    if (!eat(json_line, i, '{')) {
        return std::nullopt;
    }

    StateDeltaSummary delta;

    key = parse_json_string(json_line, i);
    if (!key || *key != "accounts") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto acc_n = parse_u64(json_line, i);
    if (!acc_n) {
        return std::nullopt;
    }
    delta.accounts = static_cast<std::size_t>(*acc_n);
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "codes") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto code_n = parse_u64(json_line, i);
    if (!code_n) {
        return std::nullopt;
    }
    delta.codes = static_cast<std::size_t>(*code_n);
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "storage") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto stor_n = parse_u64(json_line, i);
    if (!stor_n) {
        return std::nullopt;
    }
    delta.storage = static_cast<std::size_t>(*stor_n);
    if (!eat(json_line, i, ',')) {
        return std::nullopt;
    }

    key = parse_json_string(json_line, i);
    if (!key || *key != "meta") {
        return std::nullopt;
    }
    if (!eat(json_line, i, ':')) {
        return std::nullopt;
    }
    const auto meta_n = parse_u64(json_line, i);
    if (!meta_n) {
        return std::nullopt;
    }
    delta.meta = static_cast<std::size_t>(*meta_n);

    skip_ws(json_line, i);
    while (i < json_line.size() && json_line[i] == ',') {
        ++i;
        key = parse_json_string(json_line, i);
        if (!key) {
            return std::nullopt;
        }
        if (!eat(json_line, i, ':')) {
            return std::nullopt;
        }
        const auto keys = parse_string_array(json_line, i);
        if (!keys) {
            return std::nullopt;
        }
        if (*key == "account_keys") {
            delta.account_keys = *keys;
        } else if (*key == "code_keys") {
            delta.code_keys = *keys;
        } else if (*key == "storage_keys") {
            delta.storage_keys = *keys;
        } else if (*key == "meta_keys") {
            delta.meta_keys = *keys;
        } else {
            return std::nullopt;
        }
        skip_ws(json_line, i);
    }

    if (!eat(json_line, i, '}')) {
        return std::nullopt;
    }
    if (!eat(json_line, i, '}')) {
        return std::nullopt;
    }

    BlockTrace t;
    t.height = *height;
    t.block_hash = *block_hash;
    t.prev_hash = *prev_hash;
    t.protocol_version = static_cast<std::uint16_t>(*pv);
    t.state_root_before = *state_root_before;
    t.state_root_after = *state_root_after;
    t.applied_txids = *applied_txids;
    t.tx_results = *tx_results;
    t.delta = std::move(delta);
    return t;
}

}
