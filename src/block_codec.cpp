#include "rand/block_codec.hpp"

#include "rand/perf.hpp"

#include <algorithm>

namespace randio::module68 {
namespace {

[[nodiscard]] std::uint32_t read_u32_le(std::span<const std::uint8_t> bytes, const std::size_t off) {
    return static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8u) |
           (static_cast<std::uint32_t>(bytes[off + 2]) << 16u) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24u);
}

[[nodiscard]] std::uint64_t read_u64_le(std::span<const std::uint8_t> bytes, const std::size_t off) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(bytes[off + static_cast<std::size_t>(i)]) << (8u * i));
    }
    return v;
}

void append_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

}

DecodeStatus decode_header(std::span<const std::uint8_t> bytes, BlockHeader& out) {
    if (bytes.size() != header_size_bytes()) {
        return DecodeStatus::WrongSize;
    }

    out.version = read_u32_le(bytes, 0);
    out.height = read_u64_le(bytes, 4);
    std::copy(bytes.begin() + 12, bytes.begin() + 44, out.prev_block.begin());
    std::copy(bytes.begin() + 44, bytes.begin() + 76, out.merkle_root.begin());
    out.timestamp_unix_seconds = read_u64_le(bytes, 76);
    out.nonce = read_u64_le(bytes, 84);

    perf::add(static_cast<std::uint64_t>(bytes.size()));
    return DecodeStatus::Ok;
}

std::optional<BlockHeader> decode_header(std::span<const std::uint8_t> bytes) {
    BlockHeader h;
    const auto st = decode_header(bytes, h);
    if (st != DecodeStatus::Ok) {
        return std::nullopt;
    }
    return h;
}

std::vector<std::uint8_t> encode_header(const BlockHeader& h) {
    std::vector<std::uint8_t> out;
    out.reserve(header_size_bytes());

    append_u32_le(out, h.version);
    append_u64_le(out, h.height);
    out.insert(out.end(), h.prev_block.begin(), h.prev_block.end());
    out.insert(out.end(), h.merkle_root.begin(), h.merkle_root.end());
    append_u64_le(out, h.timestamp_unix_seconds);
    append_u64_le(out, h.nonce);

    perf::add(static_cast<std::uint64_t>(out.size()));
    return out;
}

}
