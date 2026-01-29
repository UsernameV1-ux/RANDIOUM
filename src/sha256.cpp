#include "rand/sha256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace randio::crypto {
namespace {

constexpr std::array<std::uint32_t, 64> K = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

constexpr std::uint32_t rotr(const std::uint32_t x, const std::uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

constexpr std::uint32_t ch(const std::uint32_t x, const std::uint32_t y, const std::uint32_t z) {
    return (x & y) ^ (~x & z);
}

constexpr std::uint32_t maj(const std::uint32_t x, const std::uint32_t y, const std::uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t big_sigma0(const std::uint32_t x) {
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

constexpr std::uint32_t big_sigma1(const std::uint32_t x) {
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

constexpr std::uint32_t small_sigma0(const std::uint32_t x) {
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

constexpr std::uint32_t small_sigma1(const std::uint32_t x) {
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

constexpr std::uint32_t load_be_u32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24u) | (static_cast<std::uint32_t>(p[1]) << 16u) |
           (static_cast<std::uint32_t>(p[2]) << 8u) | (static_cast<std::uint32_t>(p[3]));
}

constexpr void store_be_u32(std::uint8_t* p, const std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>((v >> 24u) & 0xFFu);
    p[1] = static_cast<std::uint8_t>((v >> 16u) & 0xFFu);
    p[2] = static_cast<std::uint8_t>((v >> 8u) & 0xFFu);
    p[3] = static_cast<std::uint8_t>((v) & 0xFFu);
}

struct Sha256State final {
    std::array<std::uint32_t, 8> h{
            0x6a09e667u,
            0xbb67ae85u,
            0x3c6ef372u,
            0xa54ff53au,
            0x510e527fu,
            0x9b05688cu,
            0x1f83d9abu,
            0x5be0cd19u,
    };
    std::array<std::uint8_t, 64> buffer{};
    std::size_t buffer_len{0};
    std::uint64_t total_len{0};
};

void compress(Sha256State& s, const std::uint8_t block[64]) {
    std::uint32_t w[64];
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = load_be_u32(block + i * 4);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }

    std::uint32_t a = s.h[0];
    std::uint32_t b = s.h[1];
    std::uint32_t c = s.h[2];
    std::uint32_t d = s.h[3];
    std::uint32_t e = s.h[4];
    std::uint32_t f = s.h[5];
    std::uint32_t g = s.h[6];
    std::uint32_t h = s.h[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t t1 = h + big_sigma1(e) + ch(e, f, g) + K[i] + w[i];
        const std::uint32_t t2 = big_sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    s.h[0] += a;
    s.h[1] += b;
    s.h[2] += c;
    s.h[3] += d;
    s.h[4] += e;
    s.h[5] += f;
    s.h[6] += g;
    s.h[7] += h;
}

void update(Sha256State& s, std::span<const std::uint8_t> data) {
    s.total_len += data.size();

    std::size_t i = 0;
    if (s.buffer_len != 0) {
        const std::size_t to_copy = (std::min<std::size_t>)(64 - s.buffer_len, data.size());
        std::memcpy(s.buffer.data() + s.buffer_len, data.data(), to_copy);
        s.buffer_len += to_copy;
        i += to_copy;

        if (s.buffer_len == 64) {
            compress(s, s.buffer.data());
            s.buffer_len = 0;
        }
    }

    for (; i + 64 <= data.size(); i += 64) {
        compress(s, data.data() + i);
    }

    const std::size_t remaining = data.size() - i;
    if (remaining != 0) {
        std::memcpy(s.buffer.data(), data.data() + i, remaining);
        s.buffer_len = remaining;
    }
}

Hash256 finalize(Sha256State& s) {
    const std::uint64_t bit_len = s.total_len * 8ULL;

    std::array<std::uint8_t, 128> pad{};
    std::size_t pad_len = 0;

    pad[0] = 0x80;
    pad_len = 1;

    const std::size_t mod = (s.buffer_len + pad_len) % 64;
    const std::size_t zeros = (mod <= 56) ? (56 - mod) : (56 + 64 - mod);
    pad_len += zeros;

    for (int j = 0; j < 8; ++j) {
        pad[pad_len + j] = static_cast<std::uint8_t>((bit_len >> (56 - 8 * j)) & 0xFFu);
    }
    pad_len += 8;

    update(s, std::span<const std::uint8_t>(pad.data(), pad_len));

    Hash256 out{};
    for (std::size_t i = 0; i < 8; ++i) {
        store_be_u32(out.data() + i * 4, s.h[i]);
    }
    return out;
}

}

Hash256 sha256(std::span<const std::uint8_t> data) {
    Sha256State s{};
    update(s, data);
    return finalize(s);
}

Hash256 sha256(std::string_view text) {
    return sha256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

Hash256 sha256_2x32(const Hash256& left, const Hash256& right) {
    Sha256State s{};
    update(s, std::span<const std::uint8_t>(left.data(), left.size()));
    update(s, std::span<const std::uint8_t>(right.data(), right.size()));
    return finalize(s);
}

std::string to_hex(const Hash256& h) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.resize(h.size() * 2);

    for (std::size_t i = 0; i < h.size(); ++i) {
        s[i * 2] = kHex[(h[i] >> 4u) & 0x0Fu];
        s[i * 2 + 1] = kHex[h[i] & 0x0Fu];
    }
    return s;
}

}
