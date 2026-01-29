#include "rand/storage.hpp"

#include "rand/crc32.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace randio {
namespace {

constexpr std::uint32_t kWalMagic = 0x444E4152u; // 'RAND'
constexpr std::uint32_t kSnapMagic = 0x50414E52u; // 'RNAP'
constexpr std::uint32_t kManifestMagic = 0x4E414D52u; // 'RMAN'
constexpr std::uint32_t kManifestFormatV1 = 1;

enum class WalType : std::uint8_t {
    Begin = 1,
    Put = 2,
    Erase = 3,
    Commit = 4,
};

bool read_exact(std::ifstream& in, std::uint8_t* dst, std::size_t n) {
    in.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(n));
    return in.good();
}

bool write_all(std::ofstream& out, const std::uint8_t* src, std::size_t n) {
    out.write(reinterpret_cast<const char*>(src), static_cast<std::streamsize>(n));
    return out.good();
}

}

bool Storage::load_or_init_manifest() {
    disk_schema_ = 0;
    const auto p = manifest_path();
    if (!std::filesystem::exists(p)) {
        disk_schema_ = opt_.schema_version;
        return write_manifest(disk_schema_);
    }

    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    std::uint8_t hdr[4 + 4 + 4]{};
    if (!read_exact(in, hdr, sizeof(hdr))) {
        return false;
    }
    const auto magic = decode_u32_le(hdr);
    const auto fmt = decode_u32_le(hdr + 4);
    const auto schema = decode_u32_le(hdr + 8);

    if (magic != kManifestMagic) {
        return false;
    }
    if (fmt != kManifestFormatV1) {
        return false;
    }
    if (schema == 0) {
        return false;
    }
    if (schema > opt_.schema_version) {
        return false;
    }

    disk_schema_ = schema;
    return true;
}

bool Storage::write_manifest(const std::uint32_t schema) {
    std::error_code ec;
    std::filesystem::create_directories(data_dir_, ec);
    if (ec) {
        return false;
    }

    const auto tmp = data_dir_ / "manifest.tmp";
    const auto final = manifest_path();

    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    std::vector<std::uint8_t> hdr;
    hdr.reserve(12);
    encode_u32_le(hdr, kManifestMagic);
    encode_u32_le(hdr, kManifestFormatV1);
    encode_u32_le(hdr, schema);
    if (!write_all(out, hdr.data(), hdr.size())) {
        return false;
    }

    out.flush();
    if (!out.good()) {
        return false;
    }
    out.close();

    std::filesystem::remove(final, ec);
    ec.clear();
    std::filesystem::rename(tmp, final, ec);
    if (ec) {
        return false;
    }

    return true;
}

Storage::Storage(std::filesystem::path data_dir, Options opt) : data_dir_(std::move(data_dir)), opt_(opt) {}

std::filesystem::path Storage::snapshot_path() const {
    return data_dir_ / "snapshot.dat";
}

std::filesystem::path Storage::wal_path() const {
    return data_dir_ / "wal.log";
}

std::filesystem::path Storage::manifest_path() const {
    return data_dir_ / "manifest.dat";
}

void Storage::encode_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void Storage::encode_u64_le(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

std::uint32_t Storage::decode_u32_le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
           (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
}

std::uint64_t Storage::decode_u64_le(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
    }
    return v;
}

bool Storage::open() {
    std::error_code ec;
    std::filesystem::create_directories(data_dir_, ec);
    if (ec) {
        return false;
    }

    kv_.clear();

    if (!load_or_init_manifest()) {
        return false;
    }

    if (!load_snapshot()) {
        return false;
    }

    if (!replay_wal()) {
        return false;
    }

    return true;
}

std::optional<std::vector<std::uint8_t>> Storage::get(const std::string_view key) const {
    const auto it = kv_.find(key);
    if (it == kv_.end()) {
        return std::nullopt;
    }
    return it->second;
}

Storage::Batch Storage::begin_batch() {
    static std::uint64_t next_id = 1;
    Batch b;
    b.id = next_id++;
    return b;
}

void Storage::put(Batch& b, std::string key, std::vector<std::uint8_t> value) {
    b.ops.emplace_back(std::move(key), std::optional<std::vector<std::uint8_t>>(std::move(value)));
}

void Storage::erase(Batch& b, std::string key) {
    b.ops.emplace_back(std::move(key), std::nullopt);
}

bool Storage::commit(Batch& b) {
    if (b.id == 0) {
        return false;
    }

    std::vector<std::uint8_t> payload;
    payload.reserve(8);
    encode_u64_le(payload, b.id);
    if (!append_wal_record(static_cast<std::uint8_t>(WalType::Begin), std::span<const std::uint8_t>(payload.data(), payload.size()))) {
        return false;
    }

    for (const auto& op : b.ops) {
        const auto& key = op.first;
        const auto& val = op.second;

        if (key.size() > opt_.max_key_bytes) {
            return false;
        }

        std::vector<std::uint8_t> rec;
        rec.reserve(8 + 4 + 4 + key.size() + (val ? val->size() : 0));

        encode_u64_le(rec, b.id);
        encode_u32_le(rec, static_cast<std::uint32_t>(key.size()));

        if (val) {
            if (val->size() > opt_.max_value_bytes) {
                return false;
            }
            encode_u32_le(rec, static_cast<std::uint32_t>(val->size()));
            rec.insert(rec.end(), key.begin(), key.end());
            rec.insert(rec.end(), val->begin(), val->end());
            if (!append_wal_record(static_cast<std::uint8_t>(WalType::Put), std::span<const std::uint8_t>(rec.data(), rec.size()))) {
                return false;
            }
        } else {
            encode_u32_le(rec, 0u);
            rec.insert(rec.end(), key.begin(), key.end());
            if (!append_wal_record(static_cast<std::uint8_t>(WalType::Erase), std::span<const std::uint8_t>(rec.data(), rec.size()))) {
                return false;
            }
        }
    }

    payload.clear();
    encode_u64_le(payload, b.id);
    if (!append_wal_record(static_cast<std::uint8_t>(WalType::Commit), std::span<const std::uint8_t>(payload.data(), payload.size()))) {
        return false;
    }

    for (const auto& op : b.ops) {
        if (op.second) {
            kv_[op.first] = *op.second;
        } else {
            kv_.erase(op.first);
        }
    }

    b.ops.clear();
    b.id = 0;
    return true;
}

bool Storage::append_wal_record(const std::uint8_t type, const std::span<const std::uint8_t> payload) {
    if (payload.size() > opt_.max_wal_record_bytes) {
        return false;
    }

    std::ofstream out(wal_path(), std::ios::binary | std::ios::app);
    if (!out.is_open()) {
        return false;
    }

    std::vector<std::uint8_t> header;
    header.reserve(4 + 1 + 4 + 4);
    encode_u32_le(header, kWalMagic);
    header.push_back(type);
    encode_u32_le(header, static_cast<std::uint32_t>(payload.size()));
    const auto crc = crypto::crc32_ieee(payload);
    encode_u32_le(header, crc);

    if (!write_all(out, header.data(), header.size())) {
        return false;
    }

    if (!payload.empty()) {
        if (!write_all(out, payload.data(), payload.size())) {
            return false;
        }
    }

    out.flush();
    return out.good();
}

bool Storage::load_snapshot() {
    const auto p = snapshot_path();
    if (!std::filesystem::exists(p)) {
        return true;
    }

    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    std::uint8_t hdr[4 + 4]{};
    if (!read_exact(in, hdr, sizeof(hdr))) {
        return false;
    }

    const auto magic = decode_u32_le(hdr);
    const auto schema = decode_u32_le(hdr + 4);

    if (magic != kSnapMagic || schema != disk_schema_) {
        return false;
    }

    std::uint8_t cnt_buf[8]{};
    if (!read_exact(in, cnt_buf, sizeof(cnt_buf))) {
        return false;
    }
    const auto count = decode_u64_le(cnt_buf);

    if (count > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)() / 2)) {
        return false;
    }

    for (std::uint64_t i = 0; i < count; ++i) {
        std::uint8_t lens[8]{};
        if (!read_exact(in, lens, sizeof(lens))) {
            return false;
        }
        const auto klen = decode_u32_le(lens);
        const auto vlen = decode_u32_le(lens + 4);

        if (klen > opt_.max_key_bytes || vlen > opt_.max_value_bytes) {
            return false;
        }

        std::string key;
        key.resize(klen);
        if (!read_exact(in, reinterpret_cast<std::uint8_t*>(key.data()), klen)) {
            return false;
        }

        std::vector<std::uint8_t> value;
        value.resize(vlen);
        if (vlen != 0) {
            if (!read_exact(in, value.data(), vlen)) {
                return false;
            }
        }

        kv_[std::move(key)] = std::move(value);
    }

    return true;
}

bool Storage::replay_wal() {
    const auto p = wal_path();
    if (!std::filesystem::exists(p)) {
        return true;
    }

    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    std::map<std::uint64_t, std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> > pending;
    std::uintmax_t last_good = 0;

    while (true) {
        const auto record_start = static_cast<std::uintmax_t>(in.tellg());
        std::uint8_t header[4 + 1 + 4 + 4]{};
        in.read(reinterpret_cast<char*>(header), static_cast<std::streamsize>(sizeof(header)));
        if (in.eof()) {
            break;
        }
        if (!in.good()) {
            break;
        }

        const auto magic = decode_u32_le(header);
        const auto type = header[4];
        const auto payload_len = decode_u32_le(header + 5);
        const auto want_crc = decode_u32_le(header + 9);

        if (magic != kWalMagic) {
            break;
        }
        if (payload_len > opt_.max_wal_record_bytes) {
            break;
        }

        std::vector<std::uint8_t> payload;
        payload.resize(payload_len);
        if (payload_len != 0) {
            if (!read_exact(in, payload.data(), payload_len)) {
                break;
            }
        }

        const auto got_crc = crypto::crc32_ieee(std::span<const std::uint8_t>(payload.data(), payload.size()));
        if (got_crc != want_crc) {
            break;
        }

        const auto t = static_cast<WalType>(type);
        if (t == WalType::Begin) {
            if (payload.size() != 8) {
                break;
            }
            const auto id = decode_u64_le(payload.data());
            pending[id] = {};
        } else if (t == WalType::Put || t == WalType::Erase) {
            if (payload.size() < 8 + 4 + 4) {
                break;
            }
            const auto id = decode_u64_le(payload.data());
            const auto klen = decode_u32_le(payload.data() + 8);
            const auto vlen = decode_u32_le(payload.data() + 12);

            if (klen > opt_.max_key_bytes || vlen > opt_.max_value_bytes) {
                break;
            }

            const std::size_t needed = 8 + 4 + 4 + static_cast<std::size_t>(klen) + ((t == WalType::Put) ? static_cast<std::size_t>(vlen) : 0u);
            if (payload.size() != needed) {
                break;
            }

            const auto key_start = payload.data() + 16;
            std::string key(reinterpret_cast<const char*>(key_start), reinterpret_cast<const char*>(key_start + klen));

            if (t == WalType::Put) {
                const auto val_start = key_start + klen;
                std::vector<std::uint8_t> value(val_start, val_start + vlen);
                pending[id].emplace_back(std::move(key), std::optional<std::vector<std::uint8_t>>(std::move(value)));
            } else {
                pending[id].emplace_back(std::move(key), std::nullopt);
            }
        } else if (t == WalType::Commit) {
            if (payload.size() != 8) {
                break;
            }
            const auto id = decode_u64_le(payload.data());
            const auto it = pending.find(id);
            if (it == pending.end()) {
                break;
            }

            for (const auto& op : it->second) {
                if (op.second) {
                    kv_[op.first] = *op.second;
                } else {
                    kv_.erase(op.first);
                }
            }

            pending.erase(it);
        } else {
            break;
        }

        last_good = static_cast<std::uintmax_t>(in.tellg());
        (void)record_start;
    }

    in.close();

    std::error_code ec;
    const auto sz = std::filesystem::file_size(p, ec);
    if (!ec && last_good != 0 && last_good < sz) {
        std::filesystem::resize_file(p, last_good, ec);
    }

    return true;
}

bool Storage::create_snapshot() {
    std::error_code ec;
    std::filesystem::create_directories(data_dir_, ec);
    if (ec) {
        return false;
    }

    const auto tmp = data_dir_ / "snapshot.tmp";
    const auto final = snapshot_path();

    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    std::vector<std::uint8_t> hdr;
    hdr.reserve(8);
    encode_u32_le(hdr, kSnapMagic);
    encode_u32_le(hdr, disk_schema_);
    if (!write_all(out, hdr.data(), hdr.size())) {
        return false;
    }

    std::vector<std::uint8_t> cnt;
    cnt.reserve(8);
    encode_u64_le(cnt, static_cast<std::uint64_t>(kv_.size()));
    if (!write_all(out, cnt.data(), cnt.size())) {
        return false;
    }

    for (const auto& [k, v] : kv_) {
        if (k.size() > opt_.max_key_bytes || v.size() > opt_.max_value_bytes) {
            return false;
        }

        std::vector<std::uint8_t> lens;
        lens.reserve(8);
        encode_u32_le(lens, static_cast<std::uint32_t>(k.size()));
        encode_u32_le(lens, static_cast<std::uint32_t>(v.size()));
        if (!write_all(out, lens.data(), lens.size())) {
            return false;
        }

        if (!k.empty()) {
            if (!write_all(out, reinterpret_cast<const std::uint8_t*>(k.data()), k.size())) {
                return false;
            }
        }

        if (!v.empty()) {
            if (!write_all(out, v.data(), v.size())) {
                return false;
            }
        }
    }

    out.flush();
    if (!out.good()) {
        return false;
    }
    out.close();

    std::filesystem::remove(final, ec);
    ec.clear();
    std::filesystem::rename(tmp, final, ec);
    if (ec) {
        return false;
    }

    std::ofstream wal(wal_path(), std::ios::binary | std::ios::trunc);
    return wal.good();
}

}
