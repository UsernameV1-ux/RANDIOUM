#include "rand/tx_codec.hpp"

#include "rand/perf.hpp"

namespace randio::module67 {
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

DecodeStatus decode_tx(std::span<const std::uint8_t> bytes, Transaction& out, const DecodeOptions& opt) {
    if (bytes.size() < 4 + 8 + 8 + 4) {
        return DecodeStatus::TooShort;
    }

    const auto ver = read_u32_le(bytes, 0);
    const auto nonce = read_u64_le(bytes, 4);
    if (ver >= 2) {
        if (bytes.size() < 4 + 8 + 8 + 8 + 4) {
            return DecodeStatus::TooShort;
        }
        const auto max_fee = read_u64_le(bytes, 12);
        const auto prio_fee = read_u64_le(bytes, 20);

        const auto plen_old = static_cast<std::size_t>(read_u32_le(bytes, 28));
        const bool maybe_old = (32 + plen_old == bytes.size());

        std::uint64_t compute_limit = 0;
        std::uint64_t compute_price = 0;
        std::size_t plen = plen_old;
        std::size_t payload_off = 32;

        if (!maybe_old) {
            if (bytes.size() < 4 + 8 + 8 + 8 + 8 + 8 + 4) {
                return DecodeStatus::TooShort;
            }
            compute_limit = read_u64_le(bytes, 28);
            compute_price = read_u64_le(bytes, 36);
            plen = static_cast<std::size_t>(read_u32_le(bytes, 44));
            payload_off = 48;
        }

        if (plen > opt.max_payload_bytes) {
            return DecodeStatus::PayloadTooLarge;
        }
        if (payload_off + plen != bytes.size()) {
            return DecodeStatus::LengthMismatch;
        }

        out.version = ver;
        out.nonce = nonce;
        out.fee = max_fee;
        out.max_fee_per_gas = max_fee;
        out.priority_fee_per_gas = prio_fee;
        out.compute_limit = compute_limit;
        out.compute_price_per_unit = compute_price;
        out.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(payload_off), bytes.end());
        perf::add(static_cast<std::uint64_t>(bytes.size()));
        return DecodeStatus::Ok;
    }

    const auto fee = read_u64_le(bytes, 12);
    const auto plen = static_cast<std::size_t>(read_u32_le(bytes, 20));

    if (plen > opt.max_payload_bytes) {
        return DecodeStatus::PayloadTooLarge;
    }

    if (24 + plen != bytes.size()) {
        return DecodeStatus::LengthMismatch;
    }

    out.version = ver;
    out.nonce = nonce;
    out.fee = fee;
    out.max_fee_per_gas = 0;
    out.priority_fee_per_gas = 0;
    out.compute_limit = 0;
    out.compute_price_per_unit = 0;
    out.payload.assign(bytes.begin() + 24, bytes.end());
    perf::add(static_cast<std::uint64_t>(bytes.size()));
    return DecodeStatus::Ok;
}

std::optional<Transaction> decode_tx(std::span<const std::uint8_t> bytes, const DecodeOptions& opt) {
    Transaction tx;
    const auto st = decode_tx(bytes, tx, opt);
    if (st != DecodeStatus::Ok) {
        return std::nullopt;
    }
    return tx;
}

std::vector<std::uint8_t> encode_tx(const Transaction& tx) {
    std::vector<std::uint8_t> out;
    if (tx.version >= 2) {
        if (tx.compute_limit == 0 && tx.compute_price_per_unit == 0) {
            out.reserve(4 + 8 + 8 + 8 + 4 + tx.payload.size());
        } else {
            out.reserve(4 + 8 + 8 + 8 + 8 + 8 + 4 + tx.payload.size());
        }
    } else {
        out.reserve(4 + 8 + 8 + 4 + tx.payload.size());
    }

    append_u32_le(out, tx.version);
    append_u64_le(out, tx.nonce);
    if (tx.version >= 2) {
        const auto max_fee = (tx.max_fee_per_gas != 0) ? tx.max_fee_per_gas : tx.fee;
        append_u64_le(out, max_fee);
        append_u64_le(out, tx.priority_fee_per_gas);
        if (tx.compute_limit != 0 || tx.compute_price_per_unit != 0) {
            append_u64_le(out, tx.compute_limit);
            append_u64_le(out, tx.compute_price_per_unit);
        }
    } else {
        append_u64_le(out, tx.fee);
    }
    append_u32_le(out, static_cast<std::uint32_t>(tx.payload.size()));
    out.insert(out.end(), tx.payload.begin(), tx.payload.end());

    perf::add(static_cast<std::uint64_t>(out.size()));
    return out;
}

}
