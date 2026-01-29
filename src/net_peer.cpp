#include "rand/net_peer.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace randio::net {

std::string PeerAddress::group() const {
    const auto pos = host.rfind('.');
    if (pos == std::string::npos) {
        return host;
    }
    return host.substr(0, pos);
}

std::string PeerAddress::to_string() const {
    return host + ":" + std::to_string(port);
}

PeerManager::PeerManager(Options opt) : opt_(opt) {}

void PeerManager::observe_peer(const PeerInfo& p) {
    auto it = peers_.find(p.id);
    if (it == peers_.end()) {
        peers_[p.id] = p;
        evict_if_needed_();
        return;
    }

    it->second.addr = p.addr;
    it->second.last_seen_tick = p.last_seen_tick;
}

void PeerManager::record_success(const PeerId& id) {
    auto it = peers_.find(id);
    if (it == peers_.end()) {
        return;
    }
    it->second.score += 1;
}

void PeerManager::record_failure(const PeerId& id) {
    auto it = peers_.find(id);
    if (it == peers_.end()) {
        return;
    }
    it->second.score -= 2;
}

void PeerManager::tick(const std::uint64_t now_tick) {
    for (auto& [_, p] : peers_) {
        p.last_seen_tick = (p.last_seen_tick > now_tick) ? now_tick : p.last_seen_tick;
        if (p.score > 0) {
            p.score -= 1;
        }
    }
    evict_if_needed_();
}

std::size_t PeerManager::size() const {
    return peers_.size();
}

std::vector<PeerInfo> PeerManager::select_peers(const std::size_t n) const {
    std::vector<PeerInfo> all;
    all.reserve(peers_.size());
    for (const auto& [_, p] : peers_) {
        all.push_back(p);
    }

    std::sort(all.begin(), all.end(), [](const PeerInfo& a, const PeerInfo& b) {
        if (a.score != b.score) {
            return a.score > b.score;
        }
        if (a.last_seen_tick != b.last_seen_tick) {
            return a.last_seen_tick > b.last_seen_tick;
        }
        return a.id < b.id;
    });

    std::unordered_map<std::string, std::size_t> per_group;
    std::vector<PeerInfo> out;
    out.reserve(n);

    for (const auto& p : all) {
        if (out.size() >= n) {
            break;
        }
        const auto g = p.addr.group();
        if (per_group[g] >= opt_.max_peers_per_group) {
            continue;
        }
        per_group[g] += 1;
        out.push_back(p);
    }

    return out;
}

void PeerManager::evict_if_needed_() {
    if (peers_.size() <= opt_.max_peers) {
        return;
    }

    std::vector<PeerInfo> all;
    all.reserve(peers_.size());
    for (const auto& [_, p] : peers_) {
        all.push_back(p);
    }

    std::sort(all.begin(), all.end(), [](const PeerInfo& a, const PeerInfo& b) {
        if (a.score != b.score) {
            return a.score < b.score;
        }
        return a.id > b.id;
    });

    const auto to_remove = peers_.size() - opt_.max_peers;
    for (std::size_t i = 0; i < to_remove; ++i) {
        peers_.erase(all[i].id);
    }
}

}
