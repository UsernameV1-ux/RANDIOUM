#include "rand/hash256_codec.hpp"

#include "rand/perf.hpp"

#include <algorithm>

namespace randio::module72 {
namespace {

[[nodiscard]] std::optional<std::uint8_t> nibble(const char c) {
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
}

}

std::string to_hex(const randio::crypto::Hash256& h) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.resize(64);
    for (std::size_t i = 0; i < 32; ++i) {
        const auto b = h[i];
        out[i * 2] = kDigits[(b >> 4u) & 0x0Fu];
        out[i * 2 + 1] = kDigits[b & 0x0Fu];
    }
    perf::add(static_cast<std::uint64_t>(out.size()));
    return out;
}

DecodeStatus from_hex(std::string_view s, randio::crypto::Hash256& out) {
    if (s.starts_with("0x") || s.starts_with("0X")) {
        s = s.substr(2);
    }

    if (s.size() != 64) {
        return DecodeStatus::WrongLength;
    }

    for (std::size_t i = 0; i < 32; ++i) {
        const auto hi = nibble(s[i * 2]);
        const auto lo = nibble(s[i * 2 + 1]);
        if (!hi || !lo) {
            return DecodeStatus::BadHex;
        }
        out[i] = static_cast<std::uint8_t>((*hi << 4u) | *lo);
    }

    perf::add(static_cast<std::uint64_t>(s.size()));
    return DecodeStatus::Ok;
}

std::optional<randio::crypto::Hash256> from_hex(std::string_view s) {
    randio::crypto::Hash256 h{};
    const auto st = from_hex(s, h);
    if (st != DecodeStatus::Ok) {
        return std::nullopt;
    }
    return h;
}

}
