#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "rand/net_peer.hpp"
#include "rand/net_rate.hpp"
#include "rand/p2p_frame.hpp"

namespace randio::net {

struct GossipOptions final {
    std::size_t max_payload_bytes{1024 * 1024};
    std::size_t max_dedup_entries{100000};
    std::size_t max_peer_queue{1024};
    std::size_t max_fastlane_peer_queue{256};
    TokenBucket::Options per_peer_out{TokenBucket::Options{1024 * 1024, 256 * 1024}};
    TokenBucket::Options global_out{TokenBucket::Options{8 * 1024 * 1024, 1024 * 1024}};
    TokenBucket::Options fastlane_per_peer_out{TokenBucket::Options{1024 * 1024, 256 * 1024}};
    TokenBucket::Options fastlane_global_out{TokenBucket::Options{8 * 1024 * 1024, 1024 * 1024}};

    bool enable_erasure_coding{false};
    std::uint8_t erasure_parity_shards{1};
};

struct GossipMessage final {
    std::uint16_t topic{0};
    std::vector<std::uint8_t> payload;
};

class GossipManager final {
public:
    explicit GossipManager(GossipOptions opt);

    void add_peer(const PeerId& id);
    void remove_peer(const PeerId& id);

    [[nodiscard]] bool publish(const GossipMessage& m);

    void set_mempool_overloaded(bool overloaded);

    void tick();

    [[nodiscard]] std::optional<std::pair<PeerId, ::randio::p2p::Frame>> next_outbound();

    [[nodiscard]] bool on_inbound(const PeerId& from, const ::randio::p2p::Frame& f, std::vector<GossipMessage>& out_deliver);

private:
    GossipOptions opt_{};

    bool mempool_overloaded_{false};

    TokenBucket global_out_;
    TokenBucket fastlane_global_out_;

    std::unordered_set<std::string> dedup_{};
    std::deque<std::string> dedup_fifo_{};

    struct PeerState final {
        TokenBucket out;
        TokenBucket fastlane_out;
        std::deque<::randio::p2p::Frame> fastlane_q;
        std::deque<::randio::p2p::Frame> q;
    };

    struct ErasureInflight final {
        std::uint16_t topic{0};
        std::uint32_t original_len{0};
        std::uint16_t shard_size{0};
        std::uint16_t data_shards{0};
        std::vector<std::vector<std::uint8_t>> data;
        std::vector<bool> have;
        bool have_parity{false};
        std::vector<std::uint8_t> parity;
    };

    std::unordered_map<PeerId, PeerState> peers_{};

    std::unordered_map<std::string, ErasureInflight> erasure_inflight_{};
    std::deque<std::string> erasure_fifo_{};

    [[nodiscard]] static std::string digest_key(std::uint16_t topic, const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::vector<std::uint8_t> encode_msg(const GossipMessage& m);
    [[nodiscard]] static std::optional<GossipMessage> decode_msg(const ::randio::p2p::Frame& f, std::size_t max_payload);

    void dedup_remember_(const std::string& k);
};

}
