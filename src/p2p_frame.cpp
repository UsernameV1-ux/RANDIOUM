#include "rand/p2p_frame.hpp"

#include "rand/crc32.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace randio::p2p {
namespace {

constexpr std::uint32_t kMagic = 0x444E4152u; // 'RAND'
constexpr std::size_t kHeaderSize = 16;

void put_u16_le(std::vector<std::uint8_t>& out, const std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

void put_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

std::uint16_t get_u16_le(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8u);
}

std::uint32_t get_u32_le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
           (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
}

}

std::vector<std::uint8_t> encode_frame(const Frame& f) {
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderSize + f.payload.size());

    put_u32_le(out, kMagic);
    put_u16_le(out, f.version);
    put_u16_le(out, f.message_type);
    put_u32_le(out, static_cast<std::uint32_t>(f.payload.size()));

    const auto crc = crypto::crc32_ieee(std::span<const std::uint8_t>(f.payload.data(), f.payload.size()));
    put_u32_le(out, crc);

    out.insert(out.end(), f.payload.begin(), f.payload.end());
    return out;
}

DecodeStatus decode_frame(const std::span<const std::uint8_t> data,
                          Frame& out,
                          std::size_t& bytes_consumed,
                          const DecodeOptions& opt) {
    bytes_consumed = 0;

    if (data.size() < kHeaderSize) {
        return DecodeStatus::Incomplete;
    }

    const auto magic = get_u32_le(data.data());
    if (magic != kMagic) {
        return DecodeStatus::Invalid;
    }

    const auto version = get_u16_le(data.data() + 4);
    const auto type = get_u16_le(data.data() + 6);
    const auto payload_len = get_u32_le(data.data() + 8);
    const auto want_crc = get_u32_le(data.data() + 12);

    if (payload_len > opt.max_payload_bytes) {
        return DecodeStatus::Invalid;
    }

    const std::size_t total = kHeaderSize + static_cast<std::size_t>(payload_len);
    if (data.size() < total) {
        return DecodeStatus::Incomplete;
    }

    const auto payload = data.subspan(kHeaderSize, payload_len);
    const auto got_crc = crypto::crc32_ieee(payload);
    if (got_crc != want_crc) {
        return DecodeStatus::Invalid;
    }

    out.version = version;
    out.message_type = type;
    out.payload.assign(payload.begin(), payload.end());
    bytes_consumed = total;
    return DecodeStatus::Ok;
}

}
