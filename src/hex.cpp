#include "rand/hex.hpp"

#include "rand/perf.hpp"

namespace randio::module66 {
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

std::string to_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto b = bytes[i];
        out[i * 2] = kDigits[(b >> 4u) & 0x0Fu];
        out[i * 2 + 1] = kDigits[b & 0x0Fu];
    }
    perf::add(static_cast<std::uint64_t>(out.size()));
    return out;
}

std::optional<std::vector<std::uint8_t>> from_hex(std::string_view s, const std::size_t max_bytes) {
    if (s.starts_with("0x") || s.starts_with("0X")) {
        s = s.substr(2);
    }

    if ((s.size() % 2u) != 0u) {
        return std::nullopt;
    }

    const auto nbytes = s.size() / 2u;
    if (nbytes > max_bytes) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> out;
    out.resize(nbytes);

    for (std::size_t i = 0; i < nbytes; ++i) {
        const auto hi = nibble(s[i * 2]);
        const auto lo = nibble(s[i * 2 + 1]);
        if (!hi || !lo) {
            return std::nullopt;
        }
        out[i] = static_cast<std::uint8_t>((*hi << 4u) | *lo);
    }

    perf::add(static_cast<std::uint64_t>(s.size()));
    return out;
}

}
