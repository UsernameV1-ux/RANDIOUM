#include "rand/wrap/registry.hpp"

#include "rand/hex.hpp"

#include <string>

namespace randio::module116 {
namespace {

[[nodiscard]] bool is_sym_char_(const char c) {
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

[[nodiscard]] bool sym_ok_(std::string_view s) {
    if (s.empty() || s.size() > 16) {
        return false;
    }
    for (const auto c : s) {
        if (!is_sym_char_(c)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string status_to_string_(const AssetStatus st) {
    if (st == AssetStatus::Active) {
        return "active";
    }
    return "disabled";
}

[[nodiscard]] std::optional<AssetStatus> status_from_string_(std::string_view s) {
    if (s == "active") {
        return AssetStatus::Active;
    }
    if (s == "disabled") {
        return AssetStatus::Disabled;
    }
    return std::nullopt;
}

[[nodiscard]] std::string json_escape_(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (const auto c : in) {
        if (c == '"') {
            out += "\\\"";
        } else if (c == '\\') {
            out += "\\\\";
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

[[nodiscard]] std::optional<std::string> json_get_string_(std::string_view s, std::string_view key) {
    const std::string pat = "\"" + std::string(key) + "\"";
    const auto p = s.find(pat);
    if (p == std::string_view::npos) {
        return std::nullopt;
    }
    const auto c = s.find(':', p + pat.size());
    if (c == std::string_view::npos) {
        return std::nullopt;
    }
    auto q1 = s.find('"', c + 1);
    if (q1 == std::string_view::npos) {
        return std::nullopt;
    }
    auto q2 = s.find('"', q1 + 1);
    if (q2 == std::string_view::npos) {
        return std::nullopt;
    }
    return std::string(s.substr(q1 + 1, q2 - (q1 + 1)));
}

[[nodiscard]] std::optional<std::uint64_t> json_get_u64_(std::string_view s, std::string_view key) {
    const std::string pat = "\"" + std::string(key) + "\"";
    const auto p = s.find(pat);
    if (p == std::string_view::npos) {
        return std::nullopt;
    }
    const auto c = s.find(':', p + pat.size());
    if (c == std::string_view::npos) {
        return std::nullopt;
    }
    std::size_t i = c + 1;
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
    std::uint64_t out = 0;
    for (std::size_t k = i; k < j; ++k) {
        const auto d = static_cast<std::uint64_t>(s[k] - '0');
        const auto next = out * 10 + d;
        if (next < out) {
            return std::nullopt;
        }
        out = next;
    }
    return out;
}

}

std::vector<std::uint8_t> encode_asset_info(const AssetInfo& a) {
    std::string j;
    j += "{";
    j += "\"symbol\":\"" + json_escape_(a.symbol) + "\",";
    j += "\"decimals\":" + std::to_string(a.decimals) + ",";
    j += "\"origin_chain\":\"" + json_escape_(a.origin_chain) + "\",";
    j += "\"origin_asset\":\"" + json_escape_(a.origin_asset) + "\",";
    j += "\"status\":\"" + std::string(status_to_string_(a.status)) + "\"";
    j += "}";
    return std::vector<std::uint8_t>(j.begin(), j.end());
}

std::optional<AssetInfo> decode_asset_info(const std::span<const std::uint8_t> bytes) {
    const std::string_view s(reinterpret_cast<const char*>(bytes.data()), bytes.size());

    const auto sym = json_get_string_(s, "symbol");
    const auto dec = json_get_u64_(s, "decimals");
    const auto oc = json_get_string_(s, "origin_chain");
    const auto oa = json_get_string_(s, "origin_asset");
    const auto st = json_get_string_(s, "status");

    if (!sym || !dec || !oc || !oa || !st) {
        return std::nullopt;
    }
    if (*dec > 255ULL) {
        return std::nullopt;
    }
    if (!sym_ok_(*sym)) {
        return std::nullopt;
    }
    const auto status = status_from_string_(*st);
    if (!status) {
        return std::nullopt;
    }

    AssetInfo out;
    out.symbol = *sym;
    out.decimals = static_cast<std::uint32_t>(*dec);
    out.origin_chain = *oc;
    out.origin_asset = *oa;
    out.status = *status;
    return out;
}

}
