#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace randio {

class Storage final {
public:
    struct Options final {
        std::uint32_t schema_version{1};
        std::size_t max_key_bytes{4096};
        std::size_t max_value_bytes{16 * 1024 * 1024};
        std::size_t max_wal_record_bytes{32 * 1024 * 1024};
    };

    struct Batch final {
        std::uint64_t id{0};
        std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> ops{};
    };

    explicit Storage(std::filesystem::path data_dir, Options opt);

    [[nodiscard]] bool open();

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> get(std::string_view key) const;

    [[nodiscard]] Batch begin_batch();
    void put(Batch& b, std::string key, std::vector<std::uint8_t> value);
    void erase(Batch& b, std::string key);
    [[nodiscard]] bool commit(Batch& b);

    [[nodiscard]] bool create_snapshot();

private:
    std::filesystem::path data_dir_;
    Options opt_{};

    std::map<std::string, std::vector<std::uint8_t>, std::less<>> kv_{};

    std::uint32_t disk_schema_{0};

    std::filesystem::path snapshot_path() const;
    std::filesystem::path wal_path() const;
    std::filesystem::path manifest_path() const;

    [[nodiscard]] bool load_or_init_manifest();
    [[nodiscard]] bool write_manifest(std::uint32_t schema);

    [[nodiscard]] bool load_snapshot();
    [[nodiscard]] bool replay_wal();

    [[nodiscard]] bool append_wal_record(std::uint8_t type, std::span<const std::uint8_t> payload);

    static void encode_u32_le(std::vector<std::uint8_t>& out, std::uint32_t v);
    static void encode_u64_le(std::vector<std::uint8_t>& out, std::uint64_t v);
    static std::uint32_t decode_u32_le(const std::uint8_t* p);
    static std::uint64_t decode_u64_le(const std::uint8_t* p);
};

}
