#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "rand/block.hpp"
#include "rand/sha256.hpp"

namespace randio::module82 {

struct Checkpoint final {
    std::uint64_t height{0};
    crypto::Hash256 block_hash{};
};

struct SyncOptions final {
    std::uint64_t max_headers{200000};
};

enum class AddStatus : std::uint8_t {
    Ok = 0,
    Duplicate,
    Invalid,
    RejectedByCheckpoint,
    TooManyHeaders,
};

struct HeaderInfo final {
    BlockHeader header{};
    crypto::Hash256 hash{};

    std::uint64_t height{0};
    crypto::Hash256 parent{};

    bool connected{false};
    std::uint64_t chain_work{0};
};

class LightHeaderSync final {
public:
    explicit LightHeaderSync(SyncOptions opt);

    void set_checkpoints(std::vector<Checkpoint> cps);

    [[nodiscard]] AddStatus add_header(const BlockHeader& h);

    [[nodiscard]] std::optional<BlockHeader> tip_header() const;
    [[nodiscard]] std::optional<crypto::Hash256> tip_hash() const;
    [[nodiscard]] std::optional<std::uint64_t> tip_height() const;

    [[nodiscard]] std::optional<crypto::Hash256> hash_at_height(std::uint64_t height) const;

private:
    SyncOptions opt_{};
    std::vector<Checkpoint> cps_{};

    std::unordered_map<std::string, HeaderInfo> by_hash_{};

    std::optional<std::string> tip_hash_hex_{};
    std::uint64_t tip_height_{0};

    [[nodiscard]] static std::string hex_(const crypto::Hash256& h);

    [[nodiscard]] bool checkpoint_allows_(const crypto::Hash256& tip_hash, std::uint64_t tip_height) const;
    void try_connect_(HeaderInfo& hi);
    void maybe_update_tip_(const HeaderInfo& hi);

    [[nodiscard]] std::optional<crypto::Hash256> ancestor_hash_(crypto::Hash256 tip_hash, std::uint64_t tip_height, std::uint64_t target_height) const;
};

}
