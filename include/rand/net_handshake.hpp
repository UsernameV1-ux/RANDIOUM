#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "rand/p2p_frame.hpp"
#include "rand/validator.hpp"

namespace randio::net {

struct HandshakeOptions final {
    std::uint16_t min_version{1};
    std::uint16_t max_version{1};
    std::size_t max_id_bytes{256};
    std::size_t max_seen_nonces{1024};
};

enum class HandshakeStatus : std::uint8_t {
    Ok = 0,
    Invalid = 1,
    Replay = 2,
    VersionMismatch = 3,
};

struct HandshakeHello final {
    std::uint16_t version{1};
    std::uint64_t nonce{0};
    ValidatorId node_id;
    crypto::Hash256 signature{};
};

struct HandshakeAck final {
    std::uint16_t version{1};
    std::uint64_t nonce{0};
    ValidatorId node_id;
    crypto::Hash256 signature{};
};

class HandshakeManager final {
public:
    HandshakeManager(HandshakeOptions opt, ValidatorId self, ValidatorStore keys);

    [[nodiscard]] ::randio::p2p::Frame make_hello(std::uint64_t nonce) const;

    [[nodiscard]] HandshakeStatus on_hello(const ::randio::p2p::Frame& f, HandshakeAck& out_ack);
    [[nodiscard]] HandshakeStatus on_ack(const ::randio::p2p::Frame& f);

    [[nodiscard]] bool is_authenticated(const ValidatorId& peer) const;
    [[nodiscard]] std::optional<std::uint16_t> negotiated_version(const ValidatorId& peer) const;

private:
    HandshakeOptions opt_{};
    ValidatorId self_;
    ValidatorStore keys_;

    std::unordered_set<std::string> seen_nonces_{};
    std::deque<std::string> nonce_fifo_{};
    std::unordered_set<ValidatorId> authed_{};
    std::unordered_map<ValidatorId, std::uint16_t> version_by_peer_{};

    [[nodiscard]] std::vector<std::uint8_t> hello_digest(const HandshakeHello& h) const;
    [[nodiscard]] std::vector<std::uint8_t> ack_digest(const HandshakeAck& a) const;

    [[nodiscard]] std::optional<HandshakeHello> decode_hello(const ::randio::p2p::Frame& f) const;
    [[nodiscard]] std::optional<HandshakeAck> decode_ack(const ::randio::p2p::Frame& f) const;

    [[nodiscard]] ::randio::p2p::Frame encode_hello(const HandshakeHello& h) const;
    [[nodiscard]] ::randio::p2p::Frame encode_ack(const HandshakeAck& a) const;

    [[nodiscard]] bool remember_nonce_(const ValidatorId& peer, std::uint64_t nonce);
};

}
