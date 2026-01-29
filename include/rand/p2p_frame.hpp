#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace randio::p2p {

struct Frame final {
    std::uint16_t version{1};
    std::uint16_t message_type{0};
    std::vector<std::uint8_t> payload{};
};

struct DecodeOptions final {
    std::size_t max_payload_bytes{16 * 1024 * 1024};
};

enum class DecodeStatus : std::uint8_t {
    Incomplete = 0,
    Ok = 1,
    Invalid = 2,
};

std::vector<std::uint8_t> encode_frame(const Frame& f);

DecodeStatus decode_frame(std::span<const std::uint8_t> data,
                          Frame& out,
                          std::size_t& bytes_consumed,
                          const DecodeOptions& opt);

}
