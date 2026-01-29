#pragma once

#include <cstdint>

#include "rand/sha256.hpp"
#include "rand/wrap/asset.hpp"

namespace randio {
class GlobalState;
struct StateDelta;
}

namespace randio::module116 {

enum class WrapAction : std::uint8_t {
    None = 0,
    Mint = 1,
    Burn = 2,
};

struct VerifiedWrapOp final {
    WrapAction action{WrapAction::None};
    WrappedAssetId asset{};
    crypto::Hash256 account{};
    std::uint64_t amount{0};
};

[[nodiscard]] crypto::Hash256 wrap116_balance_key(const crypto::Hash256& addr);
[[nodiscard]] crypto::Hash256 wrap116_evt_seq_key();
[[nodiscard]] crypto::Hash256 wrap116_evt_key(std::uint64_t seq);

[[nodiscard]] bool apply_bridge_mint(GlobalState& st,
                                    const WrappedAssetId& asset,
                                    const crypto::Hash256& to,
                                    std::uint64_t amount,
                                    StateDelta& out_delta);

[[nodiscard]] bool apply_bridge_burn(GlobalState& st,
                                    const WrappedAssetId& asset,
                                    const crypto::Hash256& from,
                                    std::uint64_t amount,
                                    StateDelta& out_delta);

[[nodiscard]] bool apply_verified_bridge_op(GlobalState& st,
                                           const crypto::Hash256& msg_id,
                                           const VerifiedWrapOp& op,
                                           StateDelta& out_delta);

}
