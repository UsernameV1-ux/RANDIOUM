#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "rand/tx.hpp"

namespace randio::module67 {

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    TooShort,
    LengthMismatch,
    PayloadTooLarge,
};

struct DecodeOptions final {
    std::size_t max_payload_bytes{1024 * 1024};
};

[[nodiscard]] DecodeStatus decode_tx(std::span<const std::uint8_t> bytes, Transaction& out, const DecodeOptions& opt);

[[nodiscard]] std::vector<std::uint8_t> encode_tx(const Transaction& tx);

[[nodiscard]] std::optional<Transaction> decode_tx(std::span<const std::uint8_t> bytes, const DecodeOptions& opt);

}
