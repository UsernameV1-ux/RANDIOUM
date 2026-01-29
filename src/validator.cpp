#include "rand/validator.hpp"

#include "rand/perf.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace randio {

ValidatorKeypair ValidatorKeypair::from_secret(const crypto::Hash256& secret) {
    ValidatorKeypair kp;
    kp.secret = secret;
    kp.pubkey = crypto::sha256(std::span<const std::uint8_t>(secret.data(), secret.size()));
    return kp;
}

crypto::Hash256 ValidatorKeypair::sign(const std::span<const std::uint8_t> msg) const {
    perf::add(1);
    std::vector<std::uint8_t> buf;
    buf.reserve(pubkey.size() + msg.size());
    buf.insert(buf.end(), pubkey.begin(), pubkey.end());
    buf.insert(buf.end(), msg.begin(), msg.end());
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

bool verify_signature(const crypto::Hash256& pubkey,
                      const std::span<const std::uint8_t> msg,
                      const crypto::Hash256& signature) {
    perf::add(1);
    std::vector<std::uint8_t> buf;
    buf.reserve(pubkey.size() + msg.size());
    buf.insert(buf.end(), pubkey.begin(), pubkey.end());
    buf.insert(buf.end(), msg.begin(), msg.end());
    const auto expect = crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
    return expect == signature;
}

std::vector<bool> verify_signatures_batch(const std::span<const SignatureBatchItem> items) {
    std::vector<bool> out;
    out.reserve(items.size());
    for (const auto& it : items) {
        out.push_back(verify_signature(it.pubkey, std::span<const std::uint8_t>(it.msg.data(), it.msg.size()), it.signature));
    }
    return out;
}

void ValidatorStore::add_keypair(const ValidatorId& id, const ValidatorKeypair& kp) {
    keys_[id] = kp;
}

void ValidatorStore::add_pubkey(const ValidatorId& id, const crypto::Hash256& pubkey) {
    pubkeys_[id] = pubkey;
}

std::optional<ValidatorKeypair> ValidatorStore::keypair(const ValidatorId& id) const {
    const auto it = keys_.find(id);
    if (it == keys_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<crypto::Hash256> ValidatorStore::pubkey(const ValidatorId& id) const {
    const auto it = keys_.find(id);
    if (it != keys_.end()) {
        return it->second.pubkey;
    }
    const auto it2 = pubkeys_.find(id);
    if (it2 == pubkeys_.end()) {
        return std::nullopt;
    }
    return it2->second;
}

std::vector<ValidatorId> ValidatorStore::ids() const {
    std::vector<ValidatorId> out;
    out.reserve(keys_.size() + pubkeys_.size());
    for (const auto& [id, _] : keys_) {
        out.push_back(id);
    }
    for (const auto& [id, _] : pubkeys_) {
        out.push_back(id);
    }
    std::sort(out.begin(), out.end());
    return out;
}

crypto::Hash256 hash_message(const std::span<const std::uint8_t> msg) {
    return crypto::sha256(msg);
}

crypto::Hash256 hash_message(const std::string_view msg) {
    return crypto::sha256(msg);
}

}
