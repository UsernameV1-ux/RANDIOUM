#include "rand/net_sim.hpp"

#include "rand/p2p_frame.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <utility>

namespace randio::net {

Node::Node(ValidatorId id,
           ValidatorStore keys,
           StakingLedger staking,
           crypto::Hash256 chain_seed,
           PeerManager peer_mgr,
           HandshakeManager hs,
           GossipManager gossip)
    : id_(std::move(id)), peers_(std::move(peer_mgr)), hs_(std::move(hs)), gossip_(std::move(gossip)) {
    (void)keys;
    (void)staking;
    (void)chain_seed;
}

void Node::connect(const PeerId& peer) {
    conns_[peer] = true;
    gossip_.add_peer(peer);
}

void Node::disconnect(const PeerId& peer) {
    conns_[peer] = false;
    gossip_.remove_peer(peer);
}

void Node::set_online(const bool online) {
    online_ = online;
}

bool Node::online() const {
    return online_;
}

void Node::tick(const std::uint64_t now) {
    if (!online_) {
        return;
    }
    peers_.tick(now);
    gossip_.tick();
}

const PeerId& Node::id() const {
    return id_;
}

std::vector<PeerId> Node::connections() const {
    std::vector<PeerId> out;
    out.reserve(conns_.size());
    for (const auto& [p, ok] : conns_) {
        if (ok) {
            out.push_back(p);
        }
    }
    return out;
}

PeerManager& Node::peers() {
    return peers_;
}

HandshakeManager& Node::handshake() {
    return hs_;
}

GossipManager& Node::gossiper() {
    return gossip_;
}

void Node::on_deliver(std::vector<GossipMessage> delivered) {
    inbox_.insert(inbox_.end(), delivered.begin(), delivered.end());
}

std::size_t Node::inbox_size() const {
    return inbox_.size();
}

std::vector<GossipMessage> Node::drain_inbox() {
    auto out = std::move(inbox_);
    inbox_ = {};
    return out;
}

NetworkSim::NetworkSim(NetSimOptions opt) : opt_(opt) {
    rng_state_ = (opt_.seed == 0) ? 1 : opt_.seed;
}

std::uint64_t NetworkSim::rng_next_() {
    rng_state_ = rng_state_ * 6364136223846793005ULL + 1ULL;
    return rng_state_;
}

bool NetworkSim::chance_(const std::uint64_t rate_per_million) {
    if (rate_per_million == 0) {
        return false;
    }
    const auto x = (rng_next_() >> 33u) % 1000000ULL;
    return x < rate_per_million;
}

void NetworkSim::add_node(Node n) {
    if (n.id().empty()) {
        throw std::runtime_error("node id empty");
    }
    nodes_.emplace(n.id(), std::move(n));
}

Node& NetworkSim::node(const PeerId& id) {
    auto it = nodes_.find(id);
    if (it == nodes_.end()) {
        throw std::runtime_error("node not found");
    }
    return it->second;
}

void NetworkSim::connect(const PeerId& a, const PeerId& b) {
    nodes_.at(a).connect(b);
    nodes_.at(b).connect(a);
}

void NetworkSim::disconnect(const PeerId& a, const PeerId& b) {
    nodes_.at(a).disconnect(b);
    nodes_.at(b).disconnect(a);
}

bool NetworkSim::drop_() {
    if (opt_.drop_rate_per_million == 0) {
        return false;
    }
    return chance_(opt_.drop_rate_per_million);
}

void NetworkSim::tick() {
    ++now_;

    if (opt_.dropout_rate_per_million != 0 && opt_.dropout_duration_ticks != 0) {
        std::vector<PeerId> ids;
        ids.reserve(nodes_.size());
        for (const auto& [id, _] : nodes_) {
            ids.push_back(id);
        }
        std::sort(ids.begin(), ids.end());

        for (const auto& id : ids) {
            auto& n = nodes_.at(id);
            const auto it = offline_until_.find(id);
            const bool currently_offline = (it != offline_until_.end() && it->second > now_);
            if (currently_offline) {
                n.set_online(false);
                continue;
            }
            n.set_online(true);
            if (chance_(opt_.dropout_rate_per_million)) {
                offline_until_[id] = now_ + opt_.dropout_duration_ticks;
                n.set_online(false);
            }
        }
    }

    {
        std::vector<PeerId> ids;
        ids.reserve(nodes_.size());
        for (const auto& [id, _] : nodes_) {
            ids.push_back(id);
        }
        std::sort(ids.begin(), ids.end());
        for (const auto& id : ids) {
            nodes_.at(id).tick(now_);
        }
    }

    {
        PacketBatch batch;
        std::vector<PeerId> ids;
        ids.reserve(nodes_.size());
        for (const auto& [id, _] : nodes_) {
            ids.push_back(id);
        }
        std::sort(ids.begin(), ids.end());

        for (const auto& from_id : ids) {
            auto& n = nodes_.at(from_id);
            if (!n.online()) {
                continue;
            }
            while (true) {
                auto next = n.gossiper().next_outbound();
                if (!next) {
                    break;
                }
                if (drop_()) {
                    continue;
                }

                Packet p;
                p.from = from_id;
                p.to = next->first;
                p.frame = std::move(next->second);
                p.seq = ++seq_;
                batch.add(std::move(p));

                if (chance_(opt_.duplicate_rate_per_million)) {
                    Packet dup = batch.packets().back();
                    dup.seq = ++seq_;
                    batch.add(std::move(dup));
                }
            }
        }

        batch.sort_deterministic();
        for (const auto& p : batch.packets()) {
            wire_.push_back(p);
        }
    }

    if (wire_.size() >= 2 && chance_(opt_.reorder_rate_per_million)) {
        const std::size_t i = static_cast<std::size_t>(rng_next_() % wire_.size());
        const std::size_t j = static_cast<std::size_t>(rng_next_() % wire_.size());
        if (i != j) {
            std::swap(wire_[i], wire_[j]);
        }
    }

    const std::size_t deliveries = wire_.size();
    for (std::size_t i = 0; i < deliveries; ++i) {
        auto msg = std::move(wire_.front());
        wire_.pop_front();

        auto it = nodes_.find(msg.to);
        if (it == nodes_.end()) {
            continue;
        }
        if (!it->second.online()) {
            continue;
        }

        const auto bytes = ::randio::p2p::encode_frame(msg.frame);
        ::randio::p2p::Frame decoded;
        std::size_t consumed = 0;
        ::randio::p2p::DecodeOptions dop;
        dop.max_payload_bytes = 16 * 1024 * 1024;
        const auto st = ::randio::p2p::decode_frame(bytes, decoded, consumed, dop);
        if (st != ::randio::p2p::DecodeStatus::Ok || consumed != bytes.size()) {
            continue;
        }

        std::vector<GossipMessage> out;
        [[maybe_unused]] const bool ok = it->second.gossiper().on_inbound(msg.from, decoded, out);
        if (!out.empty()) {
            it->second.on_deliver(std::move(out));
        }
    }
}

}
