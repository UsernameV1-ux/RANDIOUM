#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "rand/sha256.hpp"

namespace randio {

struct Transaction final {
    std::uint32_t version{1};
    std::uint64_t nonce{0};
    std::uint64_t fee{0};
    std::uint64_t max_fee_per_gas{0};
    std::uint64_t priority_fee_per_gas{0};
    std::uint64_t compute_limit{0};
    std::uint64_t compute_price_per_unit{0};
    std::vector<std::uint8_t> payload{};

    Transaction() = default;

    Transaction(std::uint32_t v, std::uint64_t n, std::uint64_t legacy_fee, std::vector<std::uint8_t> p)
        : version(v)
        , nonce(n)
        , fee(legacy_fee)
        , max_fee_per_gas(0)
        , priority_fee_per_gas(0)
        , compute_limit(0)
        , compute_price_per_unit(0)
        , payload(std::move(p)) {
    }

    Transaction(std::uint32_t v, std::uint64_t n, std::uint64_t max_fee, std::uint64_t prio_fee, std::vector<std::uint8_t> p)
        : version(v)
        , nonce(n)
        , fee(max_fee)
        , max_fee_per_gas(max_fee)
        , priority_fee_per_gas(prio_fee)
        , compute_limit(0)
        , compute_price_per_unit(0)
        , payload(std::move(p)) {
    }
};

std::vector<std::uint8_t> serialize_tx(const Transaction& tx);
crypto::Hash256 txid(const Transaction& tx);

}
