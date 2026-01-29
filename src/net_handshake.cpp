#include "rand/net_handshake.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace randio::net {
namespace {

constexpr std::uint16_t kMsgHello = 10;
constexpr std::uint16_t kMsgAck = 11;

void put_u16_le(std::vector<std::uint8_t>& out, const std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
}

void put_u64_le(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

std::uint16_t get_u16_le(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8u);
}

std::uint64_t get_u64_le(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
    }
    return v;
}

std::string nonce_key(const ValidatorId& id, const std::uint64_t nonce) {
    return id + ":" + std::to_string(nonce);
}

}

HandshakeManager::HandshakeManager(HandshakeOptions opt, ValidatorId self, ValidatorStore keys)
    : opt_(opt), self_(std::move(self)), keys_(std::move(keys)) {}

std::vector<std::uint8_t> HandshakeManager::hello_digest(const HandshakeHello& h) const {
    std::vector<std::uint8_t> buf;
    buf.reserve(2 + 8 + h.node_id.size());
    put_u16_le(buf, h.version);
    put_u64_le(buf, h.nonce);
    buf.insert(buf.end(), h.node_id.begin(), h.node_id.end());
    return buf;
}

std::vector<std::uint8_t> HandshakeManager::ack_digest(const HandshakeAck& a) const {
    std::vector<std::uint8_t> buf;
    buf.reserve(2 + 8 + a.node_id.size());
    put_u16_le(buf, a.version);
    put_u64_le(buf, a.nonce);
    buf.insert(buf.end(), a.node_id.begin(), a.node_id.end());
    return buf;
}

::randio::p2p::Frame HandshakeManager::encode_hello(const HandshakeHello& h) const {
    std::vector<std::uint8_t> pl;
    pl.reserve(2 + 8 + 4 + h.node_id.size() + 32);
    put_u16_le(pl, h.version);
    put_u64_le(pl, h.nonce);

    const auto id_len = static_cast<std::uint32_t>(h.node_id.size());
    pl.push_back(static_cast<std::uint8_t>(id_len & 0xFFu));
    pl.push_back(static_cast<std::uint8_t>((id_len >> 8u) & 0xFFu));
    pl.push_back(static_cast<std::uint8_t>((id_len >> 16u) & 0xFFu));
    pl.push_back(static_cast<std::uint8_t>((id_len >> 24u) & 0xFFu));

    pl.insert(pl.end(), h.node_id.begin(), h.node_id.end());
    pl.insert(pl.end(), h.signature.begin(), h.signature.end());

    ::randio::p2p::Frame f;
    f.version = 1;
    f.message_type = kMsgHello;
    f.payload = std::move(pl);
    return f;
}

::randio::p2p::Frame HandshakeManager::encode_ack(const HandshakeAck& a) const {
    std::vector<std::uint8_t> pl;
    pl.reserve(2 + 8 + 4 + a.node_id.size() + 32);
    put_u16_le(pl, a.version);
    put_u64_le(pl, a.nonce);

    const auto id_len = static_cast<std::uint32_t>(a.node_id.size());
    pl.push_back(static_cast<std::uint8_t>(id_len & 0xFFu));
    pl.push_back(static_cast<std::uint8_t>((id_len >> 8u) & 0xFFu));
    pl.push_back(static_cast<std::uint8_t>((id_len >> 16u) & 0xFFu));
    pl.push_back(static_cast<std::uint8_t>((id_len >> 24u) & 0xFFu));

    pl.insert(pl.end(), a.node_id.begin(), a.node_id.end());
    pl.insert(pl.end(), a.signature.begin(), a.signature.end());

    ::randio::p2p::Frame f;
    f.version = 1;
    f.message_type = kMsgAck;
    f.payload = std::move(pl);
    return f;
}

std::optional<HandshakeHello> HandshakeManager::decode_hello(const ::randio::p2p::Frame& f) const {
    if (f.message_type != kMsgHello) {
        return std::nullopt;
    }
    const auto& p = f.payload;
    if (p.size() < 2 + 8 + 4 + 32) {
        return std::nullopt;
    }

    HandshakeHello h;
    h.version = get_u16_le(p.data());
    h.nonce = get_u64_le(p.data() + 2);
    const auto len = static_cast<std::uint32_t>(p[10]) | (static_cast<std::uint32_t>(p[11]) << 8u) |
                     (static_cast<std::uint32_t>(p[12]) << 16u) | (static_cast<std::uint32_t>(p[13]) << 24u);

    if (len > opt_.max_id_bytes) {
        return std::nullopt;
    }

    const std::size_t need = 2 + 8 + 4 + static_cast<std::size_t>(len) + 32;
    if (p.size() != need) {
        return std::nullopt;
    }

    h.node_id.assign(reinterpret_cast<const char*>(p.data() + 14), reinterpret_cast<const char*>(p.data() + 14 + len));
    std::copy(p.end() - 32, p.end(), h.signature.begin());
    return h;
}

std::optional<HandshakeAck> HandshakeManager::decode_ack(const ::randio::p2p::Frame& f) const {
    if (f.message_type != kMsgAck) {
        return std::nullopt;
    }
    const auto& p = f.payload;
    if (p.size() < 2 + 8 + 4 + 32) {
        return std::nullopt;
    }

    HandshakeAck a;
    a.version = get_u16_le(p.data());
    a.nonce = get_u64_le(p.data() + 2);
    const auto len = static_cast<std::uint32_t>(p[10]) | (static_cast<std::uint32_t>(p[11]) << 8u) |
                     (static_cast<std::uint32_t>(p[12]) << 16u) | (static_cast<std::uint32_t>(p[13]) << 24u);

    if (len > opt_.max_id_bytes) {
        return std::nullopt;
    }

    const std::size_t need = 2 + 8 + 4 + static_cast<std::size_t>(len) + 32;
    if (p.size() != need) {
        return std::nullopt;
    }

    a.node_id.assign(reinterpret_cast<const char*>(p.data() + 14), reinterpret_cast<const char*>(p.data() + 14 + len));
    std::copy(p.end() - 32, p.end(), a.signature.begin());
    return a;
}

::randio::p2p::Frame HandshakeManager::make_hello(const std::uint64_t nonce) const {
    const auto ver = opt_.max_version;
    HandshakeHello h;
    h.version = ver;
    h.nonce = nonce;
    h.node_id = self_;

    const auto dig = hello_digest(h);
    const auto kp = keys_.keypair(self_);
    if (kp) {
        const auto sig = kp->sign(std::span<const std::uint8_t>(dig.data(), dig.size()));
        h.signature = sig;
    }

    return encode_hello(h);
}

bool HandshakeManager::remember_nonce_(const ValidatorId& peer, const std::uint64_t nonce) {
    const auto k = nonce_key(peer, nonce);
    if (seen_nonces_.find(k) != seen_nonces_.end()) {
        return false;
    }
    seen_nonces_.insert(k);
    nonce_fifo_.push_back(k);
    if (seen_nonces_.size() > opt_.max_seen_nonces) {
        const auto old = nonce_fifo_.front();
        nonce_fifo_.pop_front();
        seen_nonces_.erase(old);
    }
    return true;
}

HandshakeStatus HandshakeManager::on_hello(const ::randio::p2p::Frame& f, HandshakeAck& out_ack) {
    const auto h = decode_hello(f);
    if (!h) {
        return HandshakeStatus::Invalid;
    }

    if (h->version < opt_.min_version || h->version > opt_.max_version) {
        return HandshakeStatus::VersionMismatch;
    }

    const auto itv = version_by_peer_.find(h->node_id);
    if (itv != version_by_peer_.end() && h->version < itv->second) {
        return HandshakeStatus::VersionMismatch;
    }

    if (!remember_nonce_(h->node_id, h->nonce)) {
        return HandshakeStatus::Replay;
    }

    const auto pk = keys_.pubkey(h->node_id);
    if (!pk) {
        return HandshakeStatus::Invalid;
    }

    auto tmp = *h;
    tmp.signature = crypto::Hash256{};
    const auto dig = hello_digest(tmp);
    if (!verify_signature(*pk, std::span<const std::uint8_t>(dig.data(), dig.size()), h->signature)) {
        return HandshakeStatus::Invalid;
    }

    HandshakeAck a;
    a.version = h->version;
    a.nonce = h->nonce;
    a.node_id = self_;

    auto tmpa = a;
    const auto dig2 = ack_digest(tmpa);
    const auto self_kp = keys_.keypair(self_);
    if (!self_kp) {
        return HandshakeStatus::Invalid;
    }
    a.signature = self_kp->sign(std::span<const std::uint8_t>(dig2.data(), dig2.size()));

    out_ack = a;
    authed_.insert(h->node_id);
    version_by_peer_[h->node_id] = h->version;
    return HandshakeStatus::Ok;
}

HandshakeStatus HandshakeManager::on_ack(const ::randio::p2p::Frame& f) {
    const auto a = decode_ack(f);
    if (!a) {
        return HandshakeStatus::Invalid;
    }

    if (a->version < opt_.min_version || a->version > opt_.max_version) {
        return HandshakeStatus::VersionMismatch;
    }

    const auto itv = version_by_peer_.find(a->node_id);
    if (itv != version_by_peer_.end() && a->version < itv->second) {
        return HandshakeStatus::VersionMismatch;
    }

    if (!remember_nonce_(a->node_id, a->nonce)) {
        return HandshakeStatus::Replay;
    }

    const auto pk = keys_.pubkey(a->node_id);
    if (!pk) {
        return HandshakeStatus::Invalid;
    }

    auto tmp = *a;
    tmp.signature = crypto::Hash256{};
    const auto dig = ack_digest(tmp);
    if (!verify_signature(*pk, std::span<const std::uint8_t>(dig.data(), dig.size()), a->signature)) {
        return HandshakeStatus::Invalid;
    }

    authed_.insert(a->node_id);
    version_by_peer_[a->node_id] = a->version;
    return HandshakeStatus::Ok;
}

bool HandshakeManager::is_authenticated(const ValidatorId& peer) const {
    return authed_.find(peer) != authed_.end();
}

std::optional<std::uint16_t> HandshakeManager::negotiated_version(const ValidatorId& peer) const {
    const auto it = version_by_peer_.find(peer);
    if (it == version_by_peer_.end()) {
        return std::nullopt;
    }
    return it->second;
}

}
