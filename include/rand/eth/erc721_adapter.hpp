#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "rand/sha256.hpp"
#include "rand/state.hpp"
#include "rand/tx.hpp"

namespace randio::eth {

[[nodiscard]] crypto::Hash256 erc721_transfer_event_sig_hash();
[[nodiscard]] crypto::Hash256 erc721_approval_event_sig_hash();

[[nodiscard]] std::optional<crypto::Hash256> erc721_ownerOf(const GlobalState& st,
                                                           const crypto::Hash256& contract,
                                                           const crypto::Hash256& token_id);

[[nodiscard]] std::uint64_t erc721_balanceOf(const GlobalState& st, const crypto::Hash256& contract, std::string_view owner_id);

[[nodiscard]] std::optional<Transaction> erc721_transferFrom(GlobalState& st,
                                                            const crypto::Hash256& contract,
                                                            std::string_view from_id,
                                                            std::string_view to_id,
                                                            const crypto::Hash256& token_id);

[[nodiscard]] std::string erc721_tokenURI(const GlobalState& st, const crypto::Hash256& contract, const crypto::Hash256& token_id);

}
