#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "rand/sha256.hpp"

namespace randio {

using ValidatorId = std::string;

struct ValidatorKeypair final {
    crypto::Hash256 secret{};
    crypto::Hash256 pubkey{};

    static ValidatorKeypair from_secret(const crypto::Hash256& secret);

    [[nodiscard]] crypto::Hash256 sign(std::span<const std::uint8_t> msg) const;
};

[[nodiscard]] bool verify_signature(const crypto::Hash256& pubkey,
                                   std::span<const std::uint8_t> msg,
                                   const crypto::Hash256& signature);

struct SignatureBatchItem final {
    crypto::Hash256 pubkey{};
    std::vector<std::uint8_t> msg{};
    crypto::Hash256 signature{};
};

[[nodiscard]] std::vector<bool> verify_signatures_batch(std::span<const SignatureBatchItem> items);

struct Validator final {
    ValidatorId id;
    crypto::Hash256 pubkey{};
};

class ValidatorStore final {
public:
    void add_keypair(const ValidatorId& id, const ValidatorKeypair& kp);

    void add_pubkey(const ValidatorId& id, const crypto::Hash256& pubkey);

    [[nodiscard]] std::optional<ValidatorKeypair> keypair(const ValidatorId& id) const;
    [[nodiscard]] std::optional<crypto::Hash256> pubkey(const ValidatorId& id) const;
    [[nodiscard]] std::vector<ValidatorId> ids() const;

private:
    std::unordered_map<ValidatorId, ValidatorKeypair> keys_{};
    std::unordered_map<ValidatorId, crypto::Hash256> pubkeys_{};
};

crypto::Hash256 hash_message(std::span<const std::uint8_t> msg);
crypto::Hash256 hash_message(std::string_view msg);

}
