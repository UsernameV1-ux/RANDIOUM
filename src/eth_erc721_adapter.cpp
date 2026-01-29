#include "rand/eth/erc721_adapter.hpp"

#include <algorithm>
#include <vector>

namespace randio::eth {
namespace {

[[nodiscard]] std::vector<std::uint8_t> u64_le(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

[[nodiscard]] std::optional<std::uint64_t> parse_u64_le(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() != 8) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(bytes[static_cast<std::size_t>(i)]) << (8u * i));
    }
    return v;
}

[[nodiscard]] crypto::Hash256 randnft_supply_key() {
    return crypto::sha256("randnft:supply");
}

[[nodiscard]] crypto::Hash256 randnft_owner_key(const crypto::Hash256& token_id) {
    return crypto::sha256("randnft:owner:" + crypto::to_hex(token_id));
}

[[nodiscard]] crypto::Hash256 randnft_meta_key(const crypto::Hash256& token_id) {
    return crypto::sha256("randnft:meta:" + crypto::to_hex(token_id));
}

[[nodiscard]] crypto::Hash256 randnft_token_id(const crypto::Hash256& contract, const std::uint64_t serial) {
    const auto c = crypto::to_hex(contract);
    return crypto::sha256("randnft:token:" + c + ":" + std::to_string(serial));
}

[[nodiscard]] void append_u64_le(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

[[nodiscard]] void append_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

[[nodiscard]] Transaction make_call_tx(std::string_view caller,
                                      const std::uint64_t nonce,
                                      const std::uint64_t fee,
                                      const crypto::Hash256& contract,
                                      const std::uint64_t gas_limit,
                                      const std::span<const std::uint8_t> input,
                                      const std::uint32_t version) {
    Transaction tx;
    tx.version = version;
    tx.nonce = nonce;
    tx.fee = fee;

    std::vector<std::uint8_t> p;
    p.reserve(1 + 1 + caller.size() + 32 + 8 + 4 + input.size());
    p.push_back(static_cast<std::uint8_t>(0x03));
    p.push_back(static_cast<std::uint8_t>(caller.size()));
    p.insert(p.end(), caller.begin(), caller.end());
    p.insert(p.end(), contract.begin(), contract.end());
    append_u64_le(p, gas_limit);
    append_u32_le(p, static_cast<std::uint32_t>(input.size()));
    p.insert(p.end(), input.begin(), input.end());
    tx.payload = std::move(p);
    return tx;
}

}

crypto::Hash256 erc721_transfer_event_sig_hash() {
    return crypto::sha256("Transfer(address,address,uint256)");
}

crypto::Hash256 erc721_approval_event_sig_hash() {
    return crypto::sha256("Approval(address,address,uint256)");
}

std::optional<crypto::Hash256> erc721_ownerOf(const GlobalState& st,
                                             const crypto::Hash256& contract,
                                             const crypto::Hash256& token_id) {
    const auto ch = crypto::to_hex(contract);
    const auto v = st.get_contract_storage(ch, randnft_owner_key(token_id));
    if (!v || v->size() != 32) {
        return std::nullopt;
    }
    crypto::Hash256 out{};
    std::copy(v->begin(), v->end(), out.begin());
    return out;
}

std::uint64_t erc721_balanceOf(const GlobalState& st, const crypto::Hash256& contract, const std::string_view owner_id) {
    const auto ch = crypto::to_hex(contract);
    const auto supply_raw = st.get_contract_storage(ch, randnft_supply_key());
    std::uint64_t supply = 0;
    if (supply_raw) {
        const auto u = parse_u64_le(*supply_raw);
        if (u) {
            supply = *u;
        }
    }

    const auto owner_addr = crypto::sha256(owner_id);
    std::uint64_t cnt = 0;
    for (std::uint64_t i = 1; i <= supply; ++i) {
        const auto tid = randnft_token_id(contract, i);
        const auto o = erc721_ownerOf(st, contract, tid);
        if (o && *o == owner_addr) {
            cnt += 1;
        }
    }
    return cnt;
}

std::optional<Transaction> erc721_transferFrom(GlobalState& st,
                                              const crypto::Hash256& contract,
                                              const std::string_view from_id,
                                              const std::string_view to_id,
                                              const crypto::Hash256& token_id) {
    const auto acc = st.get_account(from_id);
    if (!acc) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> input;
    input.reserve(1 + 32 + 32);
    input.push_back(static_cast<std::uint8_t>(0x02));
    input.insert(input.end(), token_id.begin(), token_id.end());
    const auto to_addr = crypto::sha256(to_id);
    input.insert(input.end(), to_addr.begin(), to_addr.end());

    return make_call_tx(from_id,
                        acc->nonce,
                        1,
                        contract,
                        50000,
                        std::span<const std::uint8_t>(input.data(), input.size()),
                        static_cast<std::uint32_t>(st.protocol_version()));
}

std::string erc721_tokenURI(const GlobalState& st, const crypto::Hash256& contract, const crypto::Hash256& token_id) {
    const auto ch = crypto::to_hex(contract);
    const auto v = st.get_contract_storage(ch, randnft_meta_key(token_id));
    if (!v || v->empty()) {
        return {};
    }
    return std::string(v->begin(), v->end());
}

}
