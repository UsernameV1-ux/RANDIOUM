#include "rand/oracle.hpp"

#include "rand/state.hpp"
#include "rand/validator.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace randio::module117 {
namespace {

[[nodiscard]] std::vector<std::uint8_t> encode_u64_le_(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> encode_u32_le_(const std::uint32_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(4);
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
    return out;
}

[[nodiscard]] bool decode_u64_le_(const std::optional<std::vector<std::uint8_t>>& v, std::uint64_t& out) {
    if (!v) {
        out = 0;
        return true;
    }
    if (v->size() != 8) {
        return false;
    }
    std::uint64_t x = 0;
    for (int i = 0; i < 8; ++i) {
        x |= (static_cast<std::uint64_t>((*v)[static_cast<std::size_t>(i)]) << (8u * i));
    }
    out = x;
    return true;
}

[[nodiscard]] bool decode_u32_le_(const std::optional<std::vector<std::uint8_t>>& v, std::uint32_t& out) {
    if (!v) {
        out = 0;
        return true;
    }
    if (v->size() != 4) {
        return false;
    }
    const auto& b = *v;
    out = static_cast<std::uint32_t>(b[0]) | (static_cast<std::uint32_t>(b[1]) << 8u) |
          (static_cast<std::uint32_t>(b[2]) << 16u) | (static_cast<std::uint32_t>(b[3]) << 24u);
    return true;
}

[[nodiscard]] std::vector<std::uint8_t> encode_u128_le_(const unsigned __int128 v) {
    std::vector<std::uint8_t> out;
    out.reserve(16);
    for (int i = 0; i < 16; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

[[nodiscard]] bool decode_u128_le_(const std::optional<std::vector<std::uint8_t>>& v, unsigned __int128& out) {
    if (!v) {
        out = 0;
        return true;
    }
    if (v->size() != 16) {
        return false;
    }
    unsigned __int128 x = 0;
    for (int i = 0; i < 16; ++i) {
        x |= (static_cast<unsigned __int128>((*v)[static_cast<std::size_t>(i)]) << (8u * i));
    }
    out = x;
    return true;
}

[[nodiscard]] void append_u64_le_(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

[[nodiscard]] void append_u32_le_(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

[[nodiscard]] std::vector<std::uint8_t> canonical_signed_bytes_(const OracleReport& r) {
    std::vector<std::uint8_t> out;
    out.reserve(6 + 32 + 8 + 8 + 8 + 4 + 32);
    out.insert(out.end(), {'O', 'R', 'A', 'C', 'L', 'E', '1'});
    out.insert(out.end(), r.feed.id.begin(), r.feed.id.end());
    append_u64_le_(out, r.height);
    append_u64_le_(out, r.tick);
    append_u64_le_(out, r.value_u64);
    append_u32_le_(out, r.decimals);
    out.insert(out.end(), r.reporter.id.begin(), r.reporter.id.end());
    return out;
}

[[nodiscard]] crypto::Hash256 report_msg_id_(const OracleReport& r) {
    const auto msg = canonical_signed_bytes_(r);
    return crypto::sha256(std::span<const std::uint8_t>(msg.data(), msg.size()));
}

[[nodiscard]] std::string feed_hex_(const FeedId& id) {
    return crypto::to_hex(id.id);
}

[[nodiscard]] std::string reporter_hex_(const ReporterId& id) {
    return crypto::to_hex(id.id);
}

[[nodiscard]] std::string k_feed_cfg_(const FeedId& id) {
    return "oracle:feed:" + feed_hex_(id) + ":cfg";
}

[[nodiscard]] std::string k_feed_latest_(const FeedId& id) {
    return "oracle:feed:" + feed_hex_(id) + ":latest";
}

[[nodiscard]] std::string k_feed_hist_seq_(const FeedId& id) {
    return "oracle:feed:" + feed_hex_(id) + ":hist_seq";
}

[[nodiscard]] std::string k_feed_hist_n_(const FeedId& id, const std::uint64_t n) {
    return "oracle:feed:" + feed_hex_(id) + ":hist:" + std::to_string(n);
}

[[nodiscard]] std::string k_report_(const FeedId& feed, const std::uint64_t height, const std::uint64_t tick, const ReporterId& reporter) {
    return "oracle:rpt:" + feed_hex_(feed) + ":" + std::to_string(height) + ":" + std::to_string(tick) + ":" + reporter_hex_(reporter);
}

[[nodiscard]] std::string k_report_seen_(const crypto::Hash256& msg_id) {
    return "oracle:rpt_seen:" + crypto::to_hex(msg_id);
}

[[nodiscard]] std::string k_agg_(const FeedId& feed, const std::uint64_t height, const std::uint64_t tick, std::string_view field) {
    return "oracle:agg:" + feed_hex_(feed) + ":" + std::to_string(height) + ":" + std::to_string(tick) + ":" + std::string(field);
}

[[nodiscard]] std::string k_reporter_cfg_(const ReporterId& id) {
    return "oracle:reporter:" + reporter_hex_(id) + ":cfg";
}

[[nodiscard]] std::string k_reporter_index_() {
    static const auto suffix = crypto::to_hex(crypto::sha256("oracle:reporter:index"));
    return "oracle:reporter:index:" + suffix;
}

[[nodiscard]] std::vector<std::uint8_t> encode_string_list_(const std::vector<std::string>& items) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + items.size() * 8);
    append_u32_le_(out, static_cast<std::uint32_t>(items.size()));
    for (const auto& s : items) {
        append_u32_le_(out, static_cast<std::uint32_t>(s.size()));
        out.insert(out.end(), s.begin(), s.end());
    }
    return out;
}

[[nodiscard]] std::optional<std::vector<std::string>> decode_string_list_(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 4) {
        return std::nullopt;
    }
    std::size_t off = 0;
    const auto read_u32 = [&](std::uint32_t& v) -> bool {
        if (off + 4 > bytes.size()) {
            return false;
        }
        v = static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8u) |
            (static_cast<std::uint32_t>(bytes[off + 2]) << 16u) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24u);
        off += 4;
        return true;
    };

    std::uint32_t n = 0;
    if (!read_u32(n)) {
        return std::nullopt;
    }

    std::vector<std::string> out;
    out.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        std::uint32_t len = 0;
        if (!read_u32(len)) {
            return std::nullopt;
        }
        if (off + len > bytes.size()) {
            return std::nullopt;
        }
        std::string s(reinterpret_cast<const char*>(bytes.data() + off), reinterpret_cast<const char*>(bytes.data() + off + len));
        off += len;
        out.push_back(std::move(s));
    }

    if (off != bytes.size()) {
        return std::nullopt;
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> encode_feed_cfg_(const FeedConfig& c) {
    std::vector<std::uint8_t> out;
    out.reserve(32 + 4 + c.name.size() + 4 + 8 + 8 + 8 + 1);
    out.insert(out.end(), c.id.id.begin(), c.id.id.end());
    append_u32_le_(out, static_cast<std::uint32_t>(c.name.size()));
    out.insert(out.end(), c.name.begin(), c.name.end());
    append_u32_le_(out, c.decimals);
    append_u64_le_(out, c.max_history_points);
    append_u64_le_(out, c.min_quorum_weight);
    append_u64_le_(out, c.max_deviation_bps);
    out.push_back(static_cast<std::uint8_t>(c.enabled ? 1u : 0u));
    return out;
}

[[nodiscard]] std::optional<FeedConfig> decode_feed_cfg_(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 32 + 4 + 4 + 8 + 8 + 8 + 1) {
        return std::nullopt;
    }
    std::size_t off = 0;

    FeedConfig c;
    for (std::size_t i = 0; i < 32; ++i) {
        c.id.id[i] = bytes[i];
    }
    off += 32;

    const auto read_u32 = [&](std::uint32_t& v) -> bool {
        if (off + 4 > bytes.size()) {
            return false;
        }
        v = static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8u) |
            (static_cast<std::uint32_t>(bytes[off + 2]) << 16u) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24u);
        off += 4;
        return true;
    };

    const auto read_u64 = [&](std::uint64_t& v) -> bool {
        if (off + 8 > bytes.size()) {
            return false;
        }
        std::uint64_t x = 0;
        for (int i = 0; i < 8; ++i) {
            x |= (static_cast<std::uint64_t>(bytes[off + static_cast<std::size_t>(i)]) << (8u * i));
        }
        off += 8;
        v = x;
        return true;
    };

    std::uint32_t name_len = 0;
    if (!read_u32(name_len)) {
        return std::nullopt;
    }
    if (off + name_len > bytes.size()) {
        return std::nullopt;
    }
    c.name.assign(reinterpret_cast<const char*>(bytes.data() + off), reinterpret_cast<const char*>(bytes.data() + off + name_len));
    off += name_len;

    if (!read_u32(c.decimals)) {
        return std::nullopt;
    }
    if (!read_u64(c.max_history_points)) {
        return std::nullopt;
    }
    if (!read_u64(c.min_quorum_weight)) {
        return std::nullopt;
    }
    if (!read_u64(c.max_deviation_bps)) {
        return std::nullopt;
    }
    if (off + 1 > bytes.size()) {
        return std::nullopt;
    }
    c.enabled = bytes[off] != 0;
    off += 1;

    if (off != bytes.size()) {
        return std::nullopt;
    }
    return c;
}

[[nodiscard]] std::vector<std::uint8_t> encode_reporter_cfg_(const ReporterConfig& c) {
    std::vector<std::uint8_t> out;
    out.reserve(32 + 32 + 8);
    out.insert(out.end(), c.id.id.begin(), c.id.id.end());
    out.insert(out.end(), c.pubkey.begin(), c.pubkey.end());
    append_u64_le_(out, c.weight);
    return out;
}

[[nodiscard]] std::optional<ReporterConfig> decode_reporter_cfg_(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 32 + 32 + 8) {
        return std::nullopt;
    }
    ReporterConfig c;
    std::size_t off = 0;
    for (std::size_t i = 0; i < 32; ++i) {
        c.id.id[i] = bytes[off + i];
    }
    off += 32;
    for (std::size_t i = 0; i < 32; ++i) {
        c.pubkey[i] = bytes[off + i];
    }
    off += 32;
    std::uint64_t w = 0;
    for (int i = 0; i < 8; ++i) {
        w |= (static_cast<std::uint64_t>(bytes[off + static_cast<std::size_t>(i)]) << (8u * i));
    }
    c.weight = w;
    return c;
}

[[nodiscard]] std::vector<std::uint8_t> encode_price_(const PricePoint& p) {
    std::vector<std::uint8_t> out;
    out.reserve(8 + 8 + 8 + 4 + 32);
    append_u64_le_(out, p.height);
    append_u64_le_(out, p.tick);
    append_u64_le_(out, p.value_u64);
    append_u32_le_(out, p.decimals);
    out.insert(out.end(), p.source_commit.begin(), p.source_commit.end());
    return out;
}

[[nodiscard]] std::optional<PricePoint> decode_price_(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 8 + 8 + 8 + 4 + 32) {
        return std::nullopt;
    }
    auto read_u64 = [&](const std::size_t off) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= (static_cast<std::uint64_t>(bytes[off + static_cast<std::size_t>(i)]) << (8u * i));
        }
        return v;
    };
    auto read_u32 = [&](const std::size_t off) -> std::uint32_t {
        return static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8u) |
               (static_cast<std::uint32_t>(bytes[off + 2]) << 16u) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24u);
    };

    PricePoint p;
    p.height = read_u64(0);
    p.tick = read_u64(8);
    p.value_u64 = read_u64(16);
    p.decimals = read_u32(24);
    for (std::size_t i = 0; i < 32; ++i) {
        p.source_commit[i] = bytes[28 + i];
    }
    return p;
}

[[nodiscard]] std::vector<std::uint8_t> encode_report_value_(const OracleReport& r, const crypto::Hash256& msg_id) {
    std::vector<std::uint8_t> out;
    out.reserve(8 + 4 + 32);
    append_u64_le_(out, r.value_u64);
    append_u32_le_(out, r.decimals);
    out.insert(out.end(), msg_id.begin(), msg_id.end());
    return out;
}

[[nodiscard]] bool decode_report_value_(std::span<const std::uint8_t> bytes, std::uint64_t& value_u64, std::uint32_t& decimals, crypto::Hash256& msg_id) {
    if (bytes.size() != 8 + 4 + 32) {
        return false;
    }
    value_u64 = 0;
    for (int i = 0; i < 8; ++i) {
        value_u64 |= (static_cast<std::uint64_t>(bytes[static_cast<std::size_t>(i)]) << (8u * i));
    }
    decimals = static_cast<std::uint32_t>(bytes[8]) | (static_cast<std::uint32_t>(bytes[9]) << 8u) |
               (static_cast<std::uint32_t>(bytes[10]) << 16u) | (static_cast<std::uint32_t>(bytes[11]) << 24u);
    for (std::size_t i = 0; i < 32; ++i) {
        msg_id[i] = bytes[12 + i];
    }
    return true;
}

[[nodiscard]] std::optional<FeedConfig> load_feed_cfg_(GlobalState& st, const FeedId& id) {
    const auto raw = st.get_storage_entry(k_feed_cfg_(id));
    if (!raw) {
        return std::nullopt;
    }
    return decode_feed_cfg_(std::span<const std::uint8_t>(raw->data(), raw->size()));
}

[[nodiscard]] std::optional<ReporterConfig> load_reporter_cfg_(GlobalState& st, const ReporterId& id) {
    const auto raw = st.get_storage_entry(k_reporter_cfg_(id));
    if (!raw) {
        return std::nullopt;
    }
    return decode_reporter_cfg_(std::span<const std::uint8_t>(raw->data(), raw->size()));
}

[[nodiscard]] crypto::Hash256 aggregation_commit_(const FeedId& feed,
                                                 const std::uint64_t height,
                                                 const std::uint64_t tick,
                                                 const std::uint64_t sum_weight,
                                                 const unsigned __int128 sum_value_weighted,
                                                 const std::uint64_t vmin,
                                                 const std::uint64_t vmax) {
    std::vector<std::uint8_t> buf;
    buf.reserve(32 + 8 + 8 + 8 + 16 + 8 + 8);
    buf.insert(buf.end(), feed.id.begin(), feed.id.end());
    append_u64_le_(buf, height);
    append_u64_le_(buf, tick);
    append_u64_le_(buf, sum_weight);
    const auto svw = encode_u128_le_(sum_value_weighted);
    buf.insert(buf.end(), svw.begin(), svw.end());
    append_u64_le_(buf, vmin);
    append_u64_le_(buf, vmax);
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

[[nodiscard]] std::optional<std::vector<std::string>> load_reporter_index_(GlobalState& st) {
    const auto raw = st.get_storage_entry(k_reporter_index_());
    if (!raw) {
        return std::vector<std::string>{};
    }
    return decode_string_list_(std::span<const std::uint8_t>(raw->data(), raw->size()));
}

} // namespace

FeedId feed_id_from_name(const std::string_view name) {
    FeedId id;
    id.id = crypto::sha256(std::string("oracle:feed:") + std::string(name));
    return id;
}

bool feed_register(GlobalState& st, const FeedConfig& cfg, StateDelta& out_delta) {
    if (cfg.name.empty()) {
        return false;
    }
    if (cfg.decimals > 18) {
        return false;
    }
    if (cfg.max_history_points == 0) {
        return false;
    }
    if (cfg.min_quorum_weight == 0) {
        return false;
    }

    const auto key = k_feed_cfg_(cfg.id);
    const auto cur = st.get_storage_entry(key);
    const auto next = encode_feed_cfg_(cfg);
    if (cur) {
        if (*cur != next) {
            return false;
        }
        out_delta = StateDelta{};
        return true;
    }

    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    storage_changes.emplace_back(key, next);
    storage_changes.emplace_back(k_feed_hist_seq_(cfg.id), encode_u64_le_(0));
    return st.apply_batch({}, {}, storage_changes, out_delta);
}

bool reporter_register(GlobalState& st, const ReporterConfig& cfg, StateDelta& out_delta) {
    if (cfg.weight == 0) {
        return false;
    }

    const auto key = k_reporter_cfg_(cfg.id);
    const auto cur = st.get_storage_entry(key);
    const auto next = encode_reporter_cfg_(cfg);

    if (cur) {
        if (*cur != next) {
            return false;
        }
        out_delta = StateDelta{};
        return true;
    }

    const auto idx_raw = st.get_storage_entry(k_reporter_index_());
    std::vector<std::string> idx;
    if (idx_raw) {
        const auto decoded = decode_string_list_(std::span<const std::uint8_t>(idx_raw->data(), idx_raw->size()));
        if (!decoded) {
            return false;
        }
        idx = *decoded;
    }

    const auto h = reporter_hex_(cfg.id);
    idx.push_back(h);
    std::sort(idx.begin(), idx.end());
    idx.erase(std::unique(idx.begin(), idx.end()), idx.end());

    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    storage_changes.emplace_back(key, next);
    storage_changes.emplace_back(k_reporter_index_(), encode_string_list_(idx));
    return st.apply_batch({}, {}, storage_changes, out_delta);
}

OracleError apply_report(GlobalState& st, const OracleReport& rpt, StateDelta& out_delta) {
    out_delta = StateDelta{};

    const auto fc = load_feed_cfg_(st, rpt.feed);
    if (!fc || !fc->enabled) {
        return OracleError::FEED_NOT_FOUND;
    }
    if (rpt.decimals != fc->decimals) {
        return OracleError::INVALID_DECIMALS;
    }
    if (rpt.value_u64 == 0) {
        return OracleError::INVALID_VALUE;
    }

    const auto rc = load_reporter_cfg_(st, rpt.reporter);
    if (!rc) {
        return OracleError::UNAUTHORIZED_REPORTER;
    }

    const auto msg = canonical_signed_bytes_(rpt);
    if (!verify_signature(rc->pubkey, std::span<const std::uint8_t>(msg.data(), msg.size()), rpt.signature)) {
        return OracleError::INVALID_SIGNATURE;
    }

    const auto msg_id = report_msg_id_(rpt);
    if (st.get_storage_entry(k_report_seen_(msg_id))) {
        return OracleError::REPLAYED_REPORT;
    }

    const auto rpt_key = k_report_(rpt.feed, rpt.height, rpt.tick, rpt.reporter);
    if (st.get_storage_entry(rpt_key)) {
        return OracleError::DUPLICATE_REPORT;
    }

    const auto sum_w_key = k_agg_(rpt.feed, rpt.height, rpt.tick, "sum_weight");
    const auto sum_vw_key = k_agg_(rpt.feed, rpt.height, rpt.tick, "sum_value_weighted");
    const auto min_key = k_agg_(rpt.feed, rpt.height, rpt.tick, "min");
    const auto max_key = k_agg_(rpt.feed, rpt.height, rpt.tick, "max");

    std::uint64_t sum_w = 0;
    if (!decode_u64_le_(st.get_storage_entry(sum_w_key), sum_w)) {
        return OracleError::INVARIANT_FAIL;
    }

    unsigned __int128 sum_vw = 0;
    if (!decode_u128_le_(st.get_storage_entry(sum_vw_key), sum_vw)) {
        return OracleError::INVARIANT_FAIL;
    }

    std::uint64_t cur_min = 0;
    const auto min_raw = st.get_storage_entry(min_key);
    if (min_raw) {
        if (!decode_u64_le_(min_raw, cur_min)) {
            return OracleError::INVARIANT_FAIL;
        }
    } else {
        cur_min = rpt.value_u64;
    }

    std::uint64_t cur_max = 0;
    const auto max_raw = st.get_storage_entry(max_key);
    if (max_raw) {
        if (!decode_u64_le_(max_raw, cur_max)) {
            return OracleError::INVARIANT_FAIL;
        }
    } else {
        cur_max = rpt.value_u64;
    }

    const auto next_w = sum_w + rc->weight;
    if (next_w < sum_w) {
        return OracleError::OVERFLOW;
    }

    const unsigned __int128 add = static_cast<unsigned __int128>(rpt.value_u64) * static_cast<unsigned __int128>(rc->weight);
    const unsigned __int128 next_vw = sum_vw + add;
    if (next_vw < sum_vw) {
        return OracleError::OVERFLOW;
    }

    const auto next_min = (rpt.value_u64 < cur_min) ? rpt.value_u64 : cur_min;
    const auto next_max = (rpt.value_u64 > cur_max) ? rpt.value_u64 : cur_max;

    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    storage_changes.emplace_back(rpt_key, encode_report_value_(rpt, msg_id));
    storage_changes.emplace_back(k_report_seen_(msg_id), std::vector<std::uint8_t>{1});

    storage_changes.emplace_back(sum_w_key, encode_u64_le_(next_w));
    storage_changes.emplace_back(sum_vw_key, encode_u128_le_(next_vw));
    storage_changes.emplace_back(min_key, encode_u64_le_(next_min));
    storage_changes.emplace_back(max_key, encode_u64_le_(next_max));

    if (!st.apply_batch({}, {}, storage_changes, out_delta)) {
        return OracleError::INVARIANT_FAIL;
    }

    return OracleError::OK;
}

OracleError finalize_price(GlobalState& st, const FeedId feed, const std::uint64_t height, const std::uint64_t tick, StateDelta& out_delta) {
    out_delta = StateDelta{};

    const auto fc = load_feed_cfg_(st, feed);
    if (!fc || !fc->enabled) {
        return OracleError::FEED_NOT_FOUND;
    }

    const auto sum_w_key = k_agg_(feed, height, tick, "sum_weight");
    const auto sum_vw_key = k_agg_(feed, height, tick, "sum_value_weighted");
    const auto min_key = k_agg_(feed, height, tick, "min");
    const auto max_key = k_agg_(feed, height, tick, "max");

    std::uint64_t sum_w = 0;
    if (!decode_u64_le_(st.get_storage_entry(sum_w_key), sum_w)) {
        return OracleError::INVARIANT_FAIL;
    }

    unsigned __int128 sum_vw = 0;
    if (!decode_u128_le_(st.get_storage_entry(sum_vw_key), sum_vw)) {
        return OracleError::INVARIANT_FAIL;
    }

    std::uint64_t vmin = 0;
    if (!decode_u64_le_(st.get_storage_entry(min_key), vmin)) {
        return OracleError::INVARIANT_FAIL;
    }

    std::uint64_t vmax = 0;
    if (!decode_u64_le_(st.get_storage_entry(max_key), vmax)) {
        return OracleError::INVARIANT_FAIL;
    }

    if (sum_w < fc->min_quorum_weight) {
        return OracleError::INSUFFICIENT_QUORUM;
    }

    if (vmin == 0) {
        if (vmax != 0) {
            return OracleError::INVARIANT_FAIL;
        }
    } else if (vmax >= vmin) {
        const unsigned __int128 diff = static_cast<unsigned __int128>(vmax - vmin);
        const unsigned __int128 lhs = diff * static_cast<unsigned __int128>(10000);
        const unsigned __int128 rhs = static_cast<unsigned __int128>(vmin) * static_cast<unsigned __int128>(fc->max_deviation_bps);
        if (lhs > rhs) {
            return OracleError::INVARIANT_FAIL;
        }
    }

    const std::uint64_t value = (sum_w == 0) ? 0 : static_cast<std::uint64_t>(sum_vw / static_cast<unsigned __int128>(sum_w));

    PricePoint p;
    p.height = height;
    p.tick = tick;
    p.value_u64 = value;
    p.decimals = fc->decimals;
    p.source_commit = aggregation_commit_(feed, height, tick, sum_w, sum_vw, vmin, vmax);

    const auto latest_key = k_feed_latest_(feed);
    const auto cur_latest_raw = st.get_storage_entry(latest_key);
    if (cur_latest_raw) {
        const auto curp = decode_price_(std::span<const std::uint8_t>(cur_latest_raw->data(), cur_latest_raw->size()));
        if (!curp) {
            return OracleError::INVARIANT_FAIL;
        }
        if (curp->height == height && curp->tick == tick && curp->value_u64 == p.value_u64 && curp->decimals == p.decimals && curp->source_commit == p.source_commit) {
            out_delta = StateDelta{};
            return OracleError::OK;
        }
        if (curp->height == height && curp->tick == tick) {
            return OracleError::INVARIANT_FAIL;
        }
    }

    std::uint64_t seq = 0;
    if (!decode_u64_le_(st.get_storage_entry(k_feed_hist_seq_(feed)), seq)) {
        return OracleError::INVARIANT_FAIL;
    }

    const auto next_seq = seq + 1;
    if (next_seq < seq) {
        return OracleError::OVERFLOW;
    }

    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    storage_changes.emplace_back(latest_key, encode_price_(p));
    storage_changes.emplace_back(k_feed_hist_seq_(feed), encode_u64_le_(next_seq));
    storage_changes.emplace_back(k_feed_hist_n_(feed, seq), encode_price_(p));

    if (fc->max_history_points != 0 && seq >= fc->max_history_points) {
        const auto evict = seq - fc->max_history_points;
        storage_changes.emplace_back(k_feed_hist_n_(feed, evict), std::nullopt);
    }

    if (!st.apply_batch({}, {}, storage_changes, out_delta)) {
        return OracleError::INVARIANT_FAIL;
    }

    return OracleError::OK;
}

std::optional<PricePoint> get_latest(GlobalState& st, const FeedId feed) {
    const auto raw = st.get_storage_entry(k_feed_latest_(feed));
    if (!raw) {
        return std::nullopt;
    }
    return decode_price_(std::span<const std::uint8_t>(raw->data(), raw->size()));
}

std::vector<PricePoint> get_history(GlobalState& st, const FeedId feed, const std::size_t limit) {
    std::vector<PricePoint> out;
    if (limit == 0) {
        return out;
    }

    const auto fc = load_feed_cfg_(st, feed);
    if (!fc) {
        return out;
    }

    std::uint64_t seq = 0;
    if (!decode_u64_le_(st.get_storage_entry(k_feed_hist_seq_(feed)), seq)) {
        return out;
    }

    const std::uint64_t have = seq;
    std::uint64_t take = have;
    if (take > limit) {
        take = static_cast<std::uint64_t>(limit);
    }

    out.reserve(static_cast<std::size_t>(take));
    for (std::uint64_t i = 0; i < take; ++i) {
        const auto idx = (seq - 1) - i;
        const auto raw = st.get_storage_entry(k_feed_hist_n_(feed, idx));
        if (!raw) {
            continue;
        }
        const auto p = decode_price_(std::span<const std::uint8_t>(raw->data(), raw->size()));
        if (!p) {
            continue;
        }
        out.push_back(*p);
    }

    return out;
}

} // namespace randio::module117
