#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "rand/sha256.hpp"
#include "rand/state.hpp"
#include "rand/tx.hpp"

namespace randio::eth {

[[nodiscard]] crypto::Hash256 erc20_transfer_event_sig_hash();
[[nodiscard]] crypto::Hash256 erc20_approval_event_sig_hash();

[[nodiscard]] std::string erc20_name(const crypto::Hash256& contract);
[[nodiscard]] std::string erc20_symbol(const crypto::Hash256& contract);
[[nodiscard]] std::uint8_t erc20_decimals(const crypto::Hash256& contract);

[[nodiscard]] std::uint64_t erc20_totalSupply(const GlobalState& st, const crypto::Hash256& contract);
[[nodiscard]] std::uint64_t erc20_balanceOf(const GlobalState& st, const crypto::Hash256& contract, std::string_view acct_id);

[[nodiscard]] std::optional<Transaction> erc20_transfer(GlobalState& st,
                                                       const crypto::Hash256& contract,
                                                       std::string_view from_id,
                                                       std::string_view to_id,
                                                       std::uint64_t amount);

}
