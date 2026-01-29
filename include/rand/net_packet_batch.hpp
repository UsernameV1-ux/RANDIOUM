#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

#include "rand/net_peer.hpp"
#include "rand/p2p_frame.hpp"

namespace randio::net {

struct Packet final {
    PeerId from;
    PeerId to;
    ::randio::p2p::Frame frame;
    std::uint64_t seq{0};
};

class PacketBatch final {
public:
    void clear() {
        packets_.clear();
    }

    void add(Packet p) {
        packets_.push_back(std::move(p));
    }

    [[nodiscard]] const std::vector<Packet>& packets() const {
        return packets_;
    }

    void sort_deterministic() {
        std::sort(packets_.begin(), packets_.end(), [](const Packet& a, const Packet& b) {
            if (a.to != b.to) {
                return a.to < b.to;
            }
            if (a.from != b.from) {
                return a.from < b.from;
            }
            return a.seq < b.seq;
        });
    }

private:
    std::vector<Packet> packets_{};
};

}
