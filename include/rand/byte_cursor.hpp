#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace randio::module71 {

enum class ReadStatus : std::uint8_t {
    Ok = 0,
    OutOfBounds,
};

class ByteCursor final {
public:
    explicit ByteCursor(std::span<const std::uint8_t> bytes);

    [[nodiscard]] std::size_t position() const;
    [[nodiscard]] std::size_t remaining() const;
    [[nodiscard]] bool eof() const;

    [[nodiscard]] ReadStatus read_u8(std::uint8_t& out);
    [[nodiscard]] ReadStatus read_u32_le(std::uint32_t& out);
    [[nodiscard]] ReadStatus read_u64_le(std::uint64_t& out);

    [[nodiscard]] ReadStatus read_bytes(std::size_t n, std::span<const std::uint8_t>& out);

    [[nodiscard]] ReadStatus skip(std::size_t n);

private:
    std::span<const std::uint8_t> bytes_;
    std::size_t pos_{0};
};

}
