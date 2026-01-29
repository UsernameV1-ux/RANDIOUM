#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "rand/sha256.hpp"

namespace randio {

class GlobalState;
struct StateDelta;

namespace module117 {

struct FeedId final {
    crypto::Hash256 id{};
};

struct ReporterId final {
    crypto::Hash256 id{};
};

struct PricePoint final {
    std::uint64_t height{0};
    std::uint64_t tick{0};
    std::uint64_t value_u64{0};
    std::uint32_t decimals{0};
    crypto::Hash256 source_commit{};
};

enum class OracleError : std::uint8_t {
    OK = 0,
    FEED_NOT_FOUND,
    INVALID_DECIMALS,
    INVALID_VALUE,
    INVALID_SIGNATURE,
    UNAUTHORIZED_REPORTER,
    DUPLICATE_REPORT,
    INSUFFICIENT_QUORUM,
    REPLAYED_REPORT,
    OVERFLOW,
    INVARIANT_FAIL
};

struct ReporterConfig final {
    ReporterId id;
    crypto::Hash256 pubkey{};
    std::uint64_t weight{0};
};

struct FeedConfig final {
    FeedId id;
    std::string name;
    std::uint32_t decimals{0};
    std::uint64_t max_history_points{0};
    std::uint64_t min_quorum_weight{0};
    std::uint64_t max_deviation_bps{0};
    bool enabled{true};
};

struct OracleReport final {
    FeedId feed;
    std::uint64_t height{0};
    std::uint64_t tick{0};
    std::uint64_t value_u64{0};
    std::uint32_t decimals{0};
    ReporterId reporter;
    crypto::Hash256 signature{};
};

[[nodiscard]] FeedId feed_id_from_name(std::string_view name);

[[nodiscard]] bool feed_register(GlobalState& st, const FeedConfig& cfg, StateDelta& out_delta);
[[nodiscard]] bool reporter_register(GlobalState& st, const ReporterConfig& cfg, StateDelta& out_delta);

[[nodiscard]] OracleError apply_report(GlobalState& st, const OracleReport& rpt, StateDelta& out_delta);
[[nodiscard]] OracleError finalize_price(GlobalState& st, FeedId feed, std::uint64_t height, std::uint64_t tick, StateDelta& out_delta);

[[nodiscard]] std::optional<PricePoint> get_latest(GlobalState& st, FeedId feed);
[[nodiscard]] std::vector<PricePoint> get_history(GlobalState& st, FeedId feed, std::size_t limit);

} // namespace module117

} // namespace randio
