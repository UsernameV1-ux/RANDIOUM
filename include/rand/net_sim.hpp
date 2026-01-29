#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

#include "rand/consensus.hpp"
#include "rand/net_packet_batch.hpp"
#include "rand/net_gossip.hpp"
#include "rand/net_handshake.hpp"
#include "rand/net_peer.hpp"

namespace randio::net {

struct NetSimOptions final {
    std::size_t max_connections{32};
    std::uint64_t seed{1};
    std::uint64_t drop_rate_per_million{0};

    std::uint64_t duplicate_rate_per_million{0};
    std::uint64_t reorder_rate_per_million{0};

    std::uint64_t dropout_rate_per_million{0};
    std::uint64_t dropout_duration_ticks{0};
};

class Node final {
public:
    Node(ValidatorId id,
         ValidatorStore keys,
         StakingLedger staking,
         crypto::Hash256 chain_seed,
         PeerManager peer_mgr,
         HandshakeManager hs,
         GossipManager gossip);

    void connect(const PeerId& peer);

    void disconnect(const PeerId& peer);

    void set_online(bool online);
    [[nodiscard]] bool online() const;

    void tick(std::uint64_t now);

    [[nodiscard]] const PeerId& id() const;

    [[nodiscard]] std::vector<PeerId> connections() const;

    [[nodiscard]] PeerManager& peers();
    [[nodiscard]] HandshakeManager& handshake();
    [[nodiscard]] GossipManager& gossiper();

    void on_deliver(std::vector<GossipMessage> delivered);
    [[nodiscard]] std::size_t inbox_size() const;
    [[nodiscard]] std::vector<GossipMessage> drain_inbox();

private:
    ValidatorId id_;
    PeerManager peers_;
    HandshakeManager hs_;
    GossipManager gossip_;

    bool online_{true};

    std::vector<GossipMessage> inbox_{};

    std::unordered_map<PeerId, bool> conns_{};
};

class NetworkSim final {
public:
    explicit NetworkSim(NetSimOptions opt);

    void add_node(Node n);

    void connect(const PeerId& a, const PeerId& b);

    void disconnect(const PeerId& a, const PeerId& b);

    void tick();

    [[nodiscard]] Node& node(const PeerId& id);

private:
    NetSimOptions opt_{};
    std::uint64_t now_{0};

    std::uint64_t rng_state_{1};

    std::uint64_t seq_{0};

    std::unordered_map<PeerId, Node> nodes_{};
    std::deque<Packet> wire_{};

    std::unordered_map<PeerId, std::uint64_t> offline_until_{};

    [[nodiscard]] bool drop_();

    [[nodiscard]] bool chance_(std::uint64_t rate_per_million);

    [[nodiscard]] std::uint64_t rng_next_();
};

}
