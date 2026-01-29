#include "rand/crc32.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace randio::crypto {
namespace {

constexpr std::uint32_t poly = 0xEDB88320u;

constexpr std::array<std::uint32_t, 256> make_table() {
    std::array<std::uint32_t, 256> t{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? (poly ^ (c >> 1u)) : (c >> 1u);
        }
        t[i] = c;
    }
    return t;
}

constexpr std::array<std::array<std::uint32_t, 256>, 8> make_tables() {
    std::array<std::array<std::uint32_t, 256>, 8> t{};
    t[0] = make_table();
    for (std::size_t n = 1; n < t.size(); ++n) {
        for (std::size_t i = 0; i < 256; ++i) {
            const std::uint32_t c = t[n - 1][i];
            t[n][i] = t[0][c & 0xFFu] ^ (c >> 8u);
        }
    }
    return t;
}

constexpr auto table = make_tables();

[[nodiscard]] std::uint32_t load_le_u32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
           (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
}

}

std::uint32_t crc32_ieee(std::span<const std::uint8_t> data) {
    std::uint32_t c = 0xFFFFFFFFu;

    const auto* p = data.data();
    std::size_t n = data.size();

    while (n >= 8) {
        const std::uint32_t d0 = load_le_u32(p);
        const std::uint32_t d1 = load_le_u32(p + 4);

        std::uint32_t x = c ^ d0;
        c = table[7][x & 0xFFu] ^ table[6][(x >> 8u) & 0xFFu] ^ table[5][(x >> 16u) & 0xFFu] ^ table[4][x >> 24u] ^
            table[3][d1 & 0xFFu] ^ table[2][(d1 >> 8u) & 0xFFu] ^ table[1][(d1 >> 16u) & 0xFFu] ^ table[0][d1 >> 24u];

        p += 8;
        n -= 8;
    }

    for (std::size_t i = 0; i < n; ++i) {
        c = table[0][(c ^ p[i]) & 0xFFu] ^ (c >> 8u);
    }
    return c ^ 0xFFFFFFFFu;
}

}
