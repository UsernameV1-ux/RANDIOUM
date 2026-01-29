#include "rand/varint.hpp"

#include "rand/perf.hpp"

namespace randio::module70 {

std::vector<std::uint8_t> encode_u64(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    std::uint64_t x = v;
    for (;;) {
        std::uint8_t b = static_cast<std::uint8_t>(x & 0x7Fu);
        x >>= 7u;
        if (x != 0) {
            b |= 0x80u;
        }
        out.push_back(b);
        if (x == 0) {
            break;
        }
    }
    perf::add(static_cast<std::uint64_t>(out.size()));
    return out;
}

DecodeStatus decode_u64(std::span<const std::uint8_t> bytes,
                       std::uint64_t& out,
                       std::size_t& consumed,
                       const DecodeOptions& opt) {
    out = 0;
    consumed = 0;
    if (bytes.empty()) {
        return DecodeStatus::Empty;
    }

    std::uint64_t v = 0;
    int shift = 0;

    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto b = bytes[i];
        const std::uint64_t chunk = static_cast<std::uint64_t>(b & 0x7Fu);

        if (shift >= 64) {
            return DecodeStatus::TooLong;
        }

        if (shift == 63 && chunk > 1) {
            return DecodeStatus::Overflow;
        }

        v |= (chunk << static_cast<unsigned>(shift));

        consumed = i + 1;
        if ((b & 0x80u) == 0) {
            if (opt.require_canonical) {
                if (v == 0) {
                    if (consumed != 1) {
                        return DecodeStatus::NonCanonical;
                    }
                } else {
                    const auto min_shift = static_cast<unsigned>((consumed - 1) * 7u);
                    if (min_shift >= 64u) {
                        return DecodeStatus::Overflow;
                    }
                    const auto min_v = (min_shift == 63u) ? (1ull << 63u) : (1ull << min_shift);
                    if (v < min_v) {
                        return DecodeStatus::NonCanonical;
                    }
                }
            }
            out = v;
            perf::add(static_cast<std::uint64_t>(consumed));
            return DecodeStatus::Ok;
        }

        shift += 7;
        if (i == 9) {
            return DecodeStatus::TooLong;
        }
    }

    return DecodeStatus::Unterminated;
}

std::optional<std::uint64_t> decode_u64(std::span<const std::uint8_t> bytes,
                                       std::size_t& consumed,
                                       const DecodeOptions& opt) {
    std::uint64_t v = 0;
    const auto st = decode_u64(bytes, v, consumed, opt);
    if (st != DecodeStatus::Ok) {
        return std::nullopt;
    }
    return v;
}

}
