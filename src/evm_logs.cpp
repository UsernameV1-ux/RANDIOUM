#include "rand/evm_logs.hpp"

#include <algorithm>

namespace randio::module106 {

bool matches(const LogRecord& r, const TopicFilter& f) {
    if (f.address.has_value() && r.address != *f.address) {
        return false;
    }

    for (std::size_t i = 0; i < f.topics.size(); ++i) {
        if (!f.topics[i].has_value()) {
            continue;
        }
        if (i >= r.topics.size()) {
            return false;
        }
        const auto& want = *f.topics[i];
        if (want.empty()) {
            continue;
        }
        if (std::find(want.begin(), want.end(), r.topics[i]) == want.end()) {
            return false;
        }
    }

    return true;
}

std::vector<std::uint8_t> encode_u64_le(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

std::optional<std::uint64_t> decode_u64_le(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 8) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(bytes[static_cast<std::size_t>(i)]) << (8u * i));
    }
    return v;
}

std::string log_count_key(const crypto::Hash256& txid) {
    return "logs:tx:" + crypto::to_hex(txid) + ":count";
}

std::string log_entry_key(const crypto::Hash256& txid, const std::uint32_t idx) {
    return "logs:tx:" + crypto::to_hex(txid) + ":" + std::to_string(idx);
}

std::vector<std::uint8_t> encode_log_record(const LogRecord& r, const EncodeOptions& opt) {
    std::vector<std::uint8_t> out;

    const auto topics_n = r.topics.size();
    const auto data_n = r.data.size();

    if (topics_n > opt.max_topics || data_n > opt.max_data_bytes) {
        return out;
    }

    out.reserve(32 + 1 + (topics_n * 32) + 4 + data_n);

    out.insert(out.end(), r.address.begin(), r.address.end());
    out.push_back(static_cast<std::uint8_t>(topics_n));

    for (const auto& t : r.topics) {
        out.insert(out.end(), t.begin(), t.end());
    }

    const std::uint32_t len = static_cast<std::uint32_t>(data_n);
    out.push_back(static_cast<std::uint8_t>(len & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((len >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((len >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((len >> 24u) & 0xFFu));

    out.insert(out.end(), r.data.begin(), r.data.end());
    return out;
}

DecodeStatus decode_log_record(std::span<const std::uint8_t> bytes, LogRecord& out, std::size_t& consumed, const DecodeOptions& opt) {
    consumed = 0;
    out = LogRecord{};

    if (bytes.size() < 32 + 1 + 4) {
        return DecodeStatus::TooShort;
    }

    std::size_t off = 0;
    std::copy(bytes.begin(), bytes.begin() + 32, out.address.begin());
    off += 32;

    const auto topics_n = static_cast<std::size_t>(bytes[off]);
    off += 1;
    if (topics_n > opt.max_topics) {
        return DecodeStatus::SizeLimit;
    }
    if (bytes.size() < off + (topics_n * 32) + 4) {
        return DecodeStatus::TooShort;
    }

    out.topics.clear();
    out.topics.reserve(topics_n);
    for (std::size_t i = 0; i < topics_n; ++i) {
        crypto::Hash256 t{};
        std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(off),
                  bytes.begin() + static_cast<std::ptrdiff_t>(off + 32),
                  t.begin());
        out.topics.push_back(t);
        off += 32;
    }

    const std::uint32_t len = static_cast<std::uint32_t>(bytes[off]) |
                              (static_cast<std::uint32_t>(bytes[off + 1]) << 8u) |
                              (static_cast<std::uint32_t>(bytes[off + 2]) << 16u) |
                              (static_cast<std::uint32_t>(bytes[off + 3]) << 24u);
    off += 4;

    if (static_cast<std::size_t>(len) > opt.max_data_bytes) {
        return DecodeStatus::SizeLimit;
    }
    if (bytes.size() < off + static_cast<std::size_t>(len)) {
        return DecodeStatus::TooShort;
    }

    out.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(off),
                    bytes.begin() + static_cast<std::ptrdiff_t>(off + static_cast<std::size_t>(len)));
    off += static_cast<std::size_t>(len);

    consumed = off;
    return DecodeStatus::Ok;
}

}
