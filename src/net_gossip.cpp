#include "rand/net_gossip.hpp"

#include "rand/sha256.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace randio::net {
namespace {

constexpr std::uint16_t kMsgGossip = 20;
constexpr std::uint16_t kMsgGossipErasure = 21;

[[nodiscard]] bool is_fastlane_topic(const std::uint16_t topic) {
    return topic != 1;
}

void put_u16_le(std::vector<std::uint8_t>& out, const std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

void put_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

[[maybe_unused]] void put_u64_le(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

std::uint16_t get_u16_le(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8u);
}

std::uint32_t get_u32_le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
           (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
}

[[maybe_unused]] std::uint64_t get_u64_le(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
    }
    return v;
}

[[nodiscard]] crypto::Hash256 msg_id_for(const std::uint16_t topic, const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> buf;
    buf.reserve(2 + payload.size());
    put_u16_le(buf, topic);
    buf.insert(buf.end(), payload.begin(), payload.end());
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

[[nodiscard]] std::vector<std::uint8_t> encode_erasure_shard(const crypto::Hash256& msg_id,
                                                            const std::uint16_t topic,
                                                            const std::uint32_t original_len,
                                                            const std::uint16_t shard_size,
                                                            const std::uint16_t data_shards,
                                                            const std::uint16_t shard_index,
                                                            const std::vector<std::uint8_t>& shard_bytes) {
    std::vector<std::uint8_t> out;
    out.reserve(2 + 32 + 4 + 2 + 2 + 2 + 2 + shard_bytes.size());
    put_u16_le(out, topic);
    out.insert(out.end(), msg_id.begin(), msg_id.end());
    put_u32_le(out, original_len);
    put_u16_le(out, shard_size);
    put_u16_le(out, data_shards);
    put_u16_le(out, shard_index);
    put_u16_le(out, static_cast<std::uint16_t>(shard_bytes.size()));
    out.insert(out.end(), shard_bytes.begin(), shard_bytes.end());
    return out;
}

struct DecodedErasureShard final {
    crypto::Hash256 msg_id{};
    std::uint16_t topic{0};
    std::uint32_t original_len{0};
    std::uint16_t shard_size{0};
    std::uint16_t data_shards{0};
    std::uint16_t shard_index{0};
    std::vector<std::uint8_t> shard_bytes;
};

[[nodiscard]] std::optional<DecodedErasureShard> decode_erasure_shard(const ::randio::p2p::Frame& f,
                                                                     const std::size_t max_payload) {
    if (f.message_type != kMsgGossipErasure) {
        return std::nullopt;
    }
    const auto& p = f.payload;
    if (p.size() < 2 + 32 + 4 + 2 + 2 + 2 + 2) {
        return std::nullopt;
    }
    if (p.size() > max_payload) {
        return std::nullopt;
    }
    DecodedErasureShard out;
    out.topic = get_u16_le(p.data());
    std::copy(p.begin() + 2, p.begin() + 34, out.msg_id.begin());
    out.original_len = get_u32_le(p.data() + 34);
    out.shard_size = get_u16_le(p.data() + 38);
    out.data_shards = get_u16_le(p.data() + 40);
    out.shard_index = get_u16_le(p.data() + 42);
    const auto shard_len = get_u16_le(p.data() + 44);
    if (p.size() != 2 + 32 + 4 + 2 + 2 + 2 + 2 + static_cast<std::size_t>(shard_len)) {
        return std::nullopt;
    }
    out.shard_bytes.assign(p.begin() + 46, p.end());
    return out;
}

}

GossipManager::GossipManager(GossipOptions opt)
    : opt_(opt), global_out_(opt_.global_out), fastlane_global_out_(opt_.fastlane_global_out) {}

void GossipManager::set_mempool_overloaded(const bool overloaded) {
    mempool_overloaded_ = overloaded;
}

void GossipManager::add_peer(const PeerId& id) {
    if (peers_.find(id) != peers_.end()) {
        return;
    }
    PeerState st{TokenBucket(opt_.per_peer_out), TokenBucket(opt_.fastlane_per_peer_out), {}, {}};
    peers_.emplace(id, std::move(st));
}

void GossipManager::remove_peer(const PeerId& id) {
    peers_.erase(id);
}

std::string GossipManager::digest_key(const std::uint16_t topic, const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> buf;
    buf.reserve(2 + payload.size());
    put_u16_le(buf, topic);
    buf.insert(buf.end(), payload.begin(), payload.end());
    return crypto::to_hex(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
}

std::vector<std::uint8_t> GossipManager::encode_msg(const GossipMessage& m) {
    std::vector<std::uint8_t> out;
    out.reserve(2 + 4 + m.payload.size());
    put_u16_le(out, m.topic);
    put_u32_le(out, static_cast<std::uint32_t>(m.payload.size()));
    out.insert(out.end(), m.payload.begin(), m.payload.end());
    return out;
}

std::optional<GossipMessage> GossipManager::decode_msg(const ::randio::p2p::Frame& f, const std::size_t max_payload) {
    if (f.message_type != kMsgGossip) {
        return std::nullopt;
    }
    const auto& p = f.payload;
    if (p.size() < 2 + 4) {
        return std::nullopt;
    }
    const auto topic = get_u16_le(p.data());
    const auto len = get_u32_le(p.data() + 2);
    if (len > max_payload) {
        return std::nullopt;
    }
    if (p.size() != 2 + 4 + static_cast<std::size_t>(len)) {
        return std::nullopt;
    }
    GossipMessage m;
    m.topic = topic;
    m.payload.assign(p.begin() + 6, p.end());
    return m;
}

void GossipManager::dedup_remember_(const std::string& k) {
    dedup_.insert(k);
    dedup_fifo_.push_back(k);
    if (dedup_.size() > opt_.max_dedup_entries) {
        const auto old = dedup_fifo_.front();
        dedup_fifo_.pop_front();
        dedup_.erase(old);
    }
}

bool GossipManager::publish(const GossipMessage& m) {
    if (mempool_overloaded_ && m.topic == 1) {
        return false;
    }
    if (!opt_.enable_erasure_coding && m.payload.size() > opt_.max_payload_bytes) {
        return false;
    }

    const auto k = digest_key(m.topic, m.payload);
    if (dedup_.find(k) != dedup_.end()) {
        return false;
    }
    dedup_remember_(k);

    const bool fastlane = is_fastlane_topic(m.topic);

    if (!opt_.enable_erasure_coding || m.payload.size() <= opt_.max_payload_bytes) {
        ::randio::p2p::Frame f;
        f.version = 1;
        f.message_type = kMsgGossip;
        f.payload = encode_msg(m);

        for (auto& [_, ps] : peers_) {
            if (fastlane) {
                if (ps.fastlane_q.size() >= opt_.max_fastlane_peer_queue) {
                    continue;
                }
                ps.fastlane_q.push_back(f);
            } else {
                if (ps.q.size() >= opt_.max_peer_queue) {
                    continue;
                }
                ps.q.push_back(f);
            }
        }
        return true;
    }

    const auto msg_id = msg_id_for(m.topic, m.payload);
    constexpr std::size_t hdr_overhead = 46;
    if (opt_.max_payload_bytes <= hdr_overhead) {
        return false;
    }

    const auto shard_size = static_cast<std::uint16_t>((std::min<std::size_t>)(1024u, opt_.max_payload_bytes - hdr_overhead));
    const auto data_shards = static_cast<std::uint16_t>((m.payload.size() + shard_size - 1u) / shard_size);
    if (data_shards == 0) {
        return false;
    }

    std::vector<std::vector<std::uint8_t>> shards;
    shards.reserve(static_cast<std::size_t>(data_shards));
    for (std::uint16_t si = 0; si < data_shards; ++si) {
        const auto off = static_cast<std::size_t>(si) * shard_size;
        const auto n = (off >= m.payload.size()) ? 0 : (std::min<std::size_t>)(shard_size, m.payload.size() - off);
        std::vector<std::uint8_t> s;
        s.resize(shard_size, 0);
        if (n != 0) {
            std::copy(m.payload.begin() + static_cast<std::ptrdiff_t>(off),
                      m.payload.begin() + static_cast<std::ptrdiff_t>(off + n),
                      s.begin());
        }
        shards.push_back(std::move(s));
    }

    std::vector<std::uint8_t> parity;
    parity.resize(shard_size, 0);
    for (const auto& s : shards) {
        for (std::size_t i = 0; i < parity.size(); ++i) {
            parity[i] ^= s[i];
        }
    }

    std::vector<::randio::p2p::Frame> frames;
    frames.reserve(static_cast<std::size_t>(data_shards) + 1);
    for (std::uint16_t si = 0; si < data_shards; ++si) {
        ::randio::p2p::Frame f;
        f.version = 1;
        f.message_type = kMsgGossipErasure;
        f.payload = encode_erasure_shard(msg_id,
                                        m.topic,
                                        static_cast<std::uint32_t>(m.payload.size()),
                                        shard_size,
                                        data_shards,
                                        si,
                                        shards[si]);
        frames.push_back(std::move(f));
    }
    {
        ::randio::p2p::Frame f;
        f.version = 1;
        f.message_type = kMsgGossipErasure;
        f.payload = encode_erasure_shard(msg_id,
                                        m.topic,
                                        static_cast<std::uint32_t>(m.payload.size()),
                                        shard_size,
                                        data_shards,
                                        data_shards,
                                        parity);
        frames.push_back(std::move(f));
    }

    for (auto& [_, ps] : peers_) {
        if (fastlane) {
            if (ps.fastlane_q.size() + frames.size() > opt_.max_fastlane_peer_queue) {
                continue;
            }
            for (const auto& f : frames) {
                ps.fastlane_q.push_back(f);
            }
        } else {
            if (ps.q.size() + frames.size() > opt_.max_peer_queue) {
                continue;
            }
            for (const auto& f : frames) {
                ps.q.push_back(f);
            }
        }
    }

    return true;
}

void GossipManager::tick() {
    global_out_.tick();
    fastlane_global_out_.tick();
    for (auto& [_, st] : peers_) {
        st.out.tick();
        st.fastlane_out.tick();
    }
}

std::optional<std::pair<PeerId, ::randio::p2p::Frame>> GossipManager::next_outbound() {
    std::vector<PeerId> ids;
    ids.reserve(peers_.size());
    for (const auto& [pid, _] : peers_) {
        ids.push_back(pid);
    }
    std::sort(ids.begin(), ids.end());

    // Fastlane first.
    for (const auto& pid : ids) {
        auto& st = peers_.at(pid);
        if (st.fastlane_q.empty()) {
            continue;
        }
        const auto& f = st.fastlane_q.front();
        const auto cost = static_cast<std::uint64_t>(f.payload.size() + 16);
        if (!fastlane_global_out_.try_consume(cost)) {
            continue;
        }
        if (!st.fastlane_out.try_consume(cost)) {
            continue;
        }
        auto out = std::make_pair(pid, f);
        st.fastlane_q.pop_front();
        return out;
    }

    for (const auto& pid : ids) {
        auto& st = peers_.at(pid);
        if (st.q.empty()) {
            continue;
        }
        const auto& f = st.q.front();
        const auto cost = static_cast<std::uint64_t>(f.payload.size() + 16);
        if (!global_out_.try_consume(cost)) {
            return std::nullopt;
        }
        if (!st.out.try_consume(cost)) {
            continue;
        }
        auto out = std::make_pair(pid, f);
        st.q.pop_front();
        return out;
    }
    return std::nullopt;
}

bool GossipManager::on_inbound(const PeerId& from, const ::randio::p2p::Frame& f, std::vector<GossipMessage>& out_deliver) {
    (void)from;
    if (f.message_type == kMsgGossip) {
        const auto m = decode_msg(f, opt_.max_payload_bytes);
        if (!m) {
            return false;
        }
        const auto k = digest_key(m->topic, m->payload);
        if (dedup_.find(k) != dedup_.end()) {
            return true;
        }
        dedup_remember_(k);
        out_deliver.push_back(*m);
        return true;
    }

    if (!opt_.enable_erasure_coding) {
        return false;
    }

    const auto sh = decode_erasure_shard(f, opt_.max_payload_bytes);
    if (!sh) {
        return false;
    }
    if (sh->data_shards == 0 || sh->shard_size == 0) {
        return false;
    }
    if (sh->shard_bytes.size() != sh->shard_size) {
        return false;
    }
    if (sh->shard_index > sh->data_shards) {
        return false;
    }

    const auto key = crypto::to_hex(sh->msg_id);
    auto it = erasure_inflight_.find(key);
    if (it == erasure_inflight_.end()) {
        ErasureInflight st;
        st.topic = sh->topic;
        st.original_len = sh->original_len;
        st.shard_size = sh->shard_size;
        st.data_shards = sh->data_shards;
        st.data.resize(st.data_shards);
        st.have.assign(st.data_shards, false);
        st.parity.clear();
        st.have_parity = false;
        erasure_inflight_.emplace(key, std::move(st));
        erasure_fifo_.push_back(key);
        if (erasure_inflight_.size() > opt_.max_dedup_entries) {
            const auto old = erasure_fifo_.front();
            erasure_fifo_.pop_front();
            erasure_inflight_.erase(old);
        }
        it = erasure_inflight_.find(key);
    }

    auto& st = it->second;
    if (st.topic != sh->topic || st.original_len != sh->original_len || st.shard_size != sh->shard_size ||
        st.data_shards != sh->data_shards) {
        return false;
    }

    if (sh->shard_index == sh->data_shards) {
        if (!st.have_parity) {
            st.parity = sh->shard_bytes;
            st.have_parity = true;
        }
    } else {
        if (!st.have[sh->shard_index]) {
            st.data[sh->shard_index] = sh->shard_bytes;
            st.have[sh->shard_index] = true;
        }
    }

    std::size_t have_count = 0;
    std::size_t missing = st.data.size();
    for (std::size_t i = 0; i < st.have.size(); ++i) {
        if (st.have[i]) {
            have_count += 1;
        } else {
            missing = i;
        }
    }

    if (have_count < st.data.size() && !(have_count + 1 == st.data.size() && st.have_parity)) {
        return true;
    }

    if (have_count < st.data.size()) {
        std::vector<std::uint8_t> recovered;
        recovered.resize(st.shard_size, 0);
        for (std::size_t i = 0; i < recovered.size(); ++i) {
            recovered[i] = st.parity[i];
        }
        for (std::size_t si = 0; si < st.data.size(); ++si) {
            if (si == missing) {
                continue;
            }
            const auto& sbytes = st.data[si];
            for (std::size_t i = 0; i < recovered.size(); ++i) {
                recovered[i] ^= sbytes[i];
            }
        }
        st.data[missing] = std::move(recovered);
        st.have[missing] = true;
        have_count += 1;
    }

    if (have_count != st.data.size()) {
        return true;
    }

    std::vector<std::uint8_t> payload;
    payload.reserve(static_cast<std::size_t>(st.original_len));
    for (std::size_t si = 0; si < st.data.size(); ++si) {
        payload.insert(payload.end(), st.data[si].begin(), st.data[si].end());
        if (payload.size() >= st.original_len) {
            break;
        }
    }
    payload.resize(static_cast<std::size_t>(st.original_len));

    if (msg_id_for(st.topic, payload) != sh->msg_id) {
        return false;
    }

    const auto dk = digest_key(st.topic, payload);
    if (dedup_.find(dk) != dedup_.end()) {
        erasure_inflight_.erase(it);
        return true;
    }
    dedup_remember_(dk);
    erasure_inflight_.erase(it);

    GossipMessage out;
    out.topic = st.topic;
    out.payload = std::move(payload);
    out_deliver.push_back(std::move(out));
    return true;
}

}
