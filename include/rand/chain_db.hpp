#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>

#include "rand/block.hpp"
#include "rand/storage.hpp"
#include "rand/validate.hpp"

namespace randio {

class ChainDB final {
public:
    struct Tip final {
        std::uint64_t height{0};
        crypto::Hash256 hash{};
        BlockHeader header{};
    };

    struct Options final {
        Storage::Options storage{};
        ValidationOptions validation{};
    };

    explicit ChainDB(std::filesystem::path data_dir, Options opt);

    [[nodiscard]] bool open();

    [[nodiscard]] std::optional<Tip> tip() const;
    [[nodiscard]] std::optional<BlockHeader> header_by_height(std::uint64_t height) const;
    [[nodiscard]] std::optional<Block> block_by_height(std::uint64_t height) const;
    [[nodiscard]] std::optional<crypto::Hash256> state_root_by_height(std::uint64_t height) const;

    [[nodiscard]] bool verify_bootstrap(std::uint64_t height,
                                       const crypto::Hash256& expected_block_hash,
                                       const crypto::Hash256& expected_state_root) const;

    [[nodiscard]] bool put_genesis(const Block& genesis);
    [[nodiscard]] bool add_block(const Block& b);

    [[nodiscard]] bool set_state_root(std::uint64_t height, const crypto::Hash256& root);

private:
    std::filesystem::path data_dir_;
    Options opt_{};
    Storage storage_;

    [[nodiscard]] bool has_tip_() const;
    [[nodiscard]] std::optional<std::uint64_t> tip_height_() const;
    [[nodiscard]] std::optional<crypto::Hash256> tip_hash_() const;

    [[nodiscard]] bool set_tip_(std::uint64_t height, const crypto::Hash256& hash);

    void store_header_(Storage::Batch& batch, const BlockHeader& h, const crypto::Hash256& hash);
    [[nodiscard]] std::optional<BlockHeader> load_header_(std::uint64_t height) const;

    void store_block_body_(Storage::Batch& batch, std::uint64_t height, const std::vector<Transaction>& txs);
    [[nodiscard]] std::optional<std::vector<Transaction>> load_block_body_(std::uint64_t height) const;

    [[nodiscard]] bool validate_genesis_(const Block& b) const;
    [[nodiscard]] bool validate_next_(const Block& b, const BlockHeader& prev) const;

    static std::vector<std::uint8_t> u64_le(std::uint64_t v);
    static std::optional<std::uint64_t> parse_u64_le(const std::vector<std::uint8_t>& bytes);
};

}
