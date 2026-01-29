#include "rand/byte_cursor.hpp"

#include "rand/perf.hpp"

namespace randio::module71 {

ByteCursor::ByteCursor(std::span<const std::uint8_t> bytes) : bytes_(bytes), pos_(0) {}

std::size_t ByteCursor::position() const {
    return pos_;
}

std::size_t ByteCursor::remaining() const {
    if (pos_ >= bytes_.size()) {
        return 0;
    }
    return bytes_.size() - pos_;
}

bool ByteCursor::eof() const {
    return remaining() == 0;
}

ReadStatus ByteCursor::read_u8(std::uint8_t& out) {
    if (remaining() < 1) {
        return ReadStatus::OutOfBounds;
    }
    out = bytes_[pos_];
    pos_ += 1;
    perf::add(1);
    return ReadStatus::Ok;
}

ReadStatus ByteCursor::read_u32_le(std::uint32_t& out) {
    if (remaining() < 4) {
        return ReadStatus::OutOfBounds;
    }
    const auto b0 = static_cast<std::uint32_t>(bytes_[pos_ + 0]);
    const auto b1 = static_cast<std::uint32_t>(bytes_[pos_ + 1]) << 8u;
    const auto b2 = static_cast<std::uint32_t>(bytes_[pos_ + 2]) << 16u;
    const auto b3 = static_cast<std::uint32_t>(bytes_[pos_ + 3]) << 24u;
    out = b0 | b1 | b2 | b3;
    pos_ += 4;
    perf::add(4);
    return ReadStatus::Ok;
}

ReadStatus ByteCursor::read_u64_le(std::uint64_t& out) {
    if (remaining() < 8) {
        return ReadStatus::OutOfBounds;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(bytes_[pos_ + static_cast<std::size_t>(i)]) << (8u * i));
    }
    out = v;
    pos_ += 8;
    perf::add(8);
    return ReadStatus::Ok;
}

ReadStatus ByteCursor::read_bytes(const std::size_t n, std::span<const std::uint8_t>& out) {
    if (remaining() < n) {
        return ReadStatus::OutOfBounds;
    }
    out = bytes_.subspan(pos_, n);
    pos_ += n;
    perf::add(static_cast<std::uint64_t>(n));
    return ReadStatus::Ok;
}

ReadStatus ByteCursor::skip(const std::size_t n) {
    if (remaining() < n) {
        return ReadStatus::OutOfBounds;
    }
    pos_ += n;
    perf::add(static_cast<std::uint64_t>(n));
    return ReadStatus::Ok;
}

}
