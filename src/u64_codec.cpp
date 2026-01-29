#include "rand/u64_codec.hpp"

#include "rand/perf.hpp"

#include <limits>

namespace randio::module73 {

DecodeStatus parse_u64(std::string_view s, std::uint64_t& out, const DecodeOptions& opt) {
    out = 0;
    if (s.empty()) {
        return DecodeStatus::Empty;
    }

    if (opt.require_canonical) {
        if (s.size() > 1 && s[0] == '0') {
            return DecodeStatus::NonCanonical;
        }
    }

    std::uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            return DecodeStatus::BadChar;
        }
        const auto d = static_cast<std::uint64_t>(c - '0');

        if (v > (std::numeric_limits<std::uint64_t>::max)() / 10ull) {
            return DecodeStatus::Overflow;
        }
        v *= 10ull;

        if (v > (std::numeric_limits<std::uint64_t>::max)() - d) {
            return DecodeStatus::Overflow;
        }
        v += d;
    }

    out = v;
    perf::add(static_cast<std::uint64_t>(s.size()));
    return DecodeStatus::Ok;
}

std::optional<std::uint64_t> parse_u64(std::string_view s, const DecodeOptions& opt) {
    std::uint64_t v = 0;
    const auto st = parse_u64(s, v, opt);
    if (st != DecodeStatus::Ok) {
        return std::nullopt;
    }
    return v;
}

std::string format_u64(const std::uint64_t v) {
    const auto s = std::to_string(v);
    perf::add(static_cast<std::uint64_t>(s.size()));
    return s;
}

}
