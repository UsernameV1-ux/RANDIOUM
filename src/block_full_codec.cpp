#include "rand/block_full_codec.hpp"

#include "rand/block_codec.hpp"
#include "rand/perf.hpp"
#include "rand/tx_codec.hpp"

namespace randio::module69 {
namespace {

[[nodiscard]] std::uint32_t read_u32_le(std::span<const std::uint8_t> bytes, const std::size_t off) {
    return static_cast<std::uint32_t>(bytes[off]) | (static_cast<std::uint32_t>(bytes[off + 1]) << 8u) |
           (static_cast<std::uint32_t>(bytes[off + 2]) << 16u) | (static_cast<std::uint32_t>(bytes[off + 3]) << 24u);
}

void append_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

}

DecodeStatus decode_block(std::span<const std::uint8_t> bytes, Block& out, const DecodeOptions& opt) {
    if (bytes.size() < module68::header_size_bytes() + 4) {
        return DecodeStatus::TooShort;
    }
    if (bytes.size() > opt.max_block_bytes) {
        return DecodeStatus::BlockTooLarge;
    }

    BlockHeader hdr;
    const auto hst = module68::decode_header(bytes.subspan(0, module68::header_size_bytes()), hdr);
    if (hst != module68::DecodeStatus::Ok) {
        return DecodeStatus::HeaderBad;
    }

    std::size_t off = module68::header_size_bytes();
    const auto tx_count = static_cast<std::size_t>(read_u32_le(bytes, off));
    off += 4;

    if (tx_count > opt.max_txs) {
        return DecodeStatus::TooManyTxs;
    }

    out.header = hdr;
    out.transactions.clear();
    out.transactions.reserve(tx_count);

    module67::DecodeOptions txopt;
    txopt.max_payload_bytes = opt.max_tx_bytes;

    for (std::size_t i = 0; i < tx_count; ++i) {
        if (off + 4 > bytes.size()) {
            return DecodeStatus::TooShort;
        }
        const auto tlen = static_cast<std::size_t>(read_u32_le(bytes, off));
        off += 4;

        if (tlen > opt.max_tx_bytes) {
            return DecodeStatus::TxLenTooLarge;
        }
        if (off + tlen > bytes.size()) {
            return DecodeStatus::TooShort;
        }

        Transaction tx;
        const auto st = module67::decode_tx(bytes.subspan(off, tlen), tx, txopt);
        if (st != module67::DecodeStatus::Ok) {
            return DecodeStatus::TxDecodeFailed;
        }
        out.transactions.push_back(std::move(tx));
        off += tlen;
    }

    if (off != bytes.size()) {
        return DecodeStatus::LengthMismatch;
    }

    perf::add(static_cast<std::uint64_t>(bytes.size()));
    return DecodeStatus::Ok;
}

std::optional<Block> decode_block(std::span<const std::uint8_t> bytes, const DecodeOptions& opt) {
    Block b;
    const auto st = decode_block(bytes, b, opt);
    if (st != DecodeStatus::Ok) {
        return std::nullopt;
    }
    return b;
}

std::vector<std::uint8_t> encode_block(const Block& b) {
    std::vector<std::uint8_t> out;

    const auto h = module68::encode_header(b.header);
    out.insert(out.end(), h.begin(), h.end());

    append_u32_le(out, static_cast<std::uint32_t>(b.transactions.size()));

    for (const auto& tx : b.transactions) {
        const auto tb = module67::encode_tx(tx);
        append_u32_le(out, static_cast<std::uint32_t>(tb.size()));
        out.insert(out.end(), tb.begin(), tb.end());
    }

    perf::add(static_cast<std::uint64_t>(out.size()));
    return out;
}

}
