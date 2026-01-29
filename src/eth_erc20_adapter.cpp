#include "rand/eth/erc20_adapter.hpp"

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

[[nodiscard]] crypto::Hash256 rand20_supply_key() {
    return crypto::sha256("rand20:supply");
}

[[nodiscard]] crypto::Hash256 rand20_balance_key(const crypto::Hash256& addr) {
    return crypto::sha256("rand20:bal:" + crypto::to_hex(addr));
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

crypto::Hash256 erc20_transfer_event_sig_hash() {
    return crypto::sha256("Transfer(address,address,uint256)");
}

crypto::Hash256 erc20_approval_event_sig_hash() {
    return crypto::sha256("Approval(address,address,uint256)");
}

std::string erc20_name(const crypto::Hash256&) {
    return "MRD-20";
}

std::string erc20_symbol(const crypto::Hash256&) {
    return "MRD20";
}

std::uint8_t erc20_decimals(const crypto::Hash256&) {
    return 0;
}

std::uint64_t erc20_totalSupply(const GlobalState& st, const crypto::Hash256& contract) {
    const auto ch = crypto::to_hex(contract);
    const auto v = st.get_contract_storage(ch, rand20_supply_key());
    if (!v) {
        return 0;
    }
    const auto u = parse_u64_le(*v);
    if (!u) {
        return 0;
    }
    return *u;
}

std::uint64_t erc20_balanceOf(const GlobalState& st, const crypto::Hash256& contract, const std::string_view acct_id) {
    const auto ch = crypto::to_hex(contract);
    const auto addr = crypto::sha256(acct_id);
    const auto v = st.get_contract_storage(ch, rand20_balance_key(addr));
    if (!v) {
        return 0;
    }
    const auto u = parse_u64_le(*v);
    if (!u) {
        return 0;
    }
    return *u;
}

std::optional<Transaction> erc20_transfer(GlobalState& st,
                                         const crypto::Hash256& contract,
                                         const std::string_view from_id,
                                         const std::string_view to_id,
                                         const std::uint64_t amount) {
    if (amount == 0) {
        return std::nullopt;
    }

    const auto acc = st.get_account(from_id);
    if (!acc) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> input;
    input.reserve(1 + 32 + 8);
    input.push_back(static_cast<std::uint8_t>(0x01));
    const auto to_addr = crypto::sha256(to_id);
    input.insert(input.end(), to_addr.begin(), to_addr.end());
    const auto ab = u64_le(amount);
    input.insert(input.end(), ab.begin(), ab.end());

    return make_call_tx(from_id,
                        acc->nonce,
                        1,
                        contract,
                        50000,
                        std::span<const std::uint8_t>(input.data(), input.size()),
                        static_cast<std::uint32_t>(st.protocol_version()));
}

}
