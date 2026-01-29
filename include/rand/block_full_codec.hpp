#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "rand/block.hpp"

namespace randio::module69 {

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    TooShort,
    HeaderBad,
    TooManyTxs,
    TxLenTooLarge,
    BlockTooLarge,
    TxDecodeFailed,
    LengthMismatch,
};

struct DecodeOptions final {
    std::size_t max_txs{10000};
    std::size_t max_tx_bytes{1024 * 1024};
    std::size_t max_block_bytes{16 * 1024 * 1024};
};

[[nodiscard]] DecodeStatus decode_block(std::span<const std::uint8_t> bytes, Block& out, const DecodeOptions& opt);

[[nodiscard]] std::optional<Block> decode_block(std::span<const std::uint8_t> bytes, const DecodeOptions& opt);

[[nodiscard]] std::vector<std::uint8_t> encode_block(const Block& b);

}
