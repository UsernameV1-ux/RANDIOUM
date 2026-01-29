#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace randio::net {

using PeerId = std::string;

struct PeerAddress final {
    std::string host;
    std::uint16_t port{0};

    [[nodiscard]] std::string group() const;
    [[nodiscard]] std::string to_string() const;
};

struct PeerInfo final {
    PeerId id;
    PeerAddress addr;

    std::int64_t score{0};
    std::uint64_t last_seen_tick{0};
};

class PeerManager final {
public:
    struct Options final {
        std::size_t max_peers{128};
        std::size_t max_peers_per_group{8};
        std::uint64_t seed{1};
    };

    explicit PeerManager(Options opt);

    void observe_peer(const PeerInfo& p);

    [[nodiscard]] std::vector<PeerInfo> select_peers(std::size_t n) const;

    void record_success(const PeerId& id);
    void record_failure(const PeerId& id);

    void tick(std::uint64_t now_tick);

    [[nodiscard]] std::size_t size() const;

private:
    Options opt_{};
    std::unordered_map<PeerId, PeerInfo> peers_{};

    void evict_if_needed_();
};

}
