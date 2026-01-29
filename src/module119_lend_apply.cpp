#include "rand/module119/lend/apply.hpp"

#include "rand/oracle.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace randio::module119::lend {
namespace {

constexpr std::uint8_t kOpConfigure = 0x01;
constexpr std::uint8_t kOpDeposit = 0x02;
constexpr std::uint8_t kOpWithdraw = 0x03;
constexpr std::uint8_t kOpBorrow = 0x04;
constexpr std::uint8_t kOpRepay = 0x05;
constexpr std::uint8_t kOpLiquidate = 0x06;
constexpr std::uint8_t kOpAccrueInterest = 0x07;

constexpr std::uint64_t kOracleMaxStaleBlocks = 10;

struct Config final {
    crypto::Hash256 asset_id{};
    std::uint64_t collateral_factor_bps{0};
    std::uint64_t liquidation_threshold_bps{0};
    std::uint64_t interest_rate_bps_per_epoch{0};
    std::uint64_t reserve_factor_bps{0};
    bool initialized{false};
};

[[nodiscard]] std::optional<std::uint64_t> decode_u64_(std::span<const std::uint8_t> b) {
    if (b.size() != 8) {
        return std::nullopt;
    }
    std::uint64_t x = 0;
    for (int i = 0; i < 8; ++i) {
        x |= (static_cast<std::uint64_t>(b[static_cast<std::size_t>(i)]) << (8u * i));
    }
    return x;
}

[[nodiscard]] std::vector<std::uint8_t> encode_u64_(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

[[nodiscard]] bool read_u64_at_(std::span<const std::uint8_t> b, std::size_t& off, std::uint64_t& out) {
    if (off + 8 > b.size()) {
        return false;
    }
    const auto v = decode_u64_(std::span<const std::uint8_t>(b.data() + off, 8));
    if (!v) {
        return false;
    }
    out = *v;
    off += 8;
    return true;
}

[[nodiscard]] std::optional<crypto::Hash256> read_hash256_at_(std::span<const std::uint8_t> b, std::size_t& off) {
    if (off + 32 > b.size()) {
        return std::nullopt;
    }
    crypto::Hash256 out{};
    std::copy(b.begin() + static_cast<std::ptrdiff_t>(off), b.begin() + static_cast<std::ptrdiff_t>(off + 32), out.begin());
    off += 32;
    return out;
}

[[nodiscard]] bool read_len_string_(std::span<const std::uint8_t> b, std::size_t& off, std::string& out) {
    if (off >= b.size()) {
        return false;
    }
    const auto len = static_cast<std::size_t>(b[off]);
    off += 1;
    if (len == 0) {
        return false;
    }
    if (off + len > b.size()) {
        return false;
    }
    out.assign(reinterpret_cast<const char*>(b.data() + off), reinterpret_cast<const char*>(b.data() + off + len));
    off += len;
    return true;
}

[[nodiscard]] crypto::Hash256 key_(std::string_view contract_hex, std::string_view suffix) {
    return crypto::sha256("lend119:" + std::string(suffix) + ":" + std::string(contract_hex));
}

[[nodiscard]] crypto::Hash256 k_cfg_asset_(std::string_view contract_hex) { return key_(contract_hex, "cfg:asset"); }
[[nodiscard]] crypto::Hash256 k_cfg_collateral_factor_bps_(std::string_view contract_hex) { return key_(contract_hex, "cfg:collateral_factor_bps"); }
[[nodiscard]] crypto::Hash256 k_cfg_liq_threshold_bps_(std::string_view contract_hex) { return key_(contract_hex, "cfg:liquidation_threshold_bps"); }
[[nodiscard]] crypto::Hash256 k_cfg_interest_bps_(std::string_view contract_hex) { return key_(contract_hex, "cfg:interest_rate_bps_per_epoch"); }
[[nodiscard]] crypto::Hash256 k_cfg_reserve_bps_(std::string_view contract_hex) { return key_(contract_hex, "cfg:reserve_factor_bps"); }
[[nodiscard]] crypto::Hash256 k_cfg_init_(std::string_view contract_hex) { return key_(contract_hex, "cfg:initialized"); }

[[nodiscard]] crypto::Hash256 k_tot_shares_(std::string_view contract_hex) { return key_(contract_hex, "tot_shares"); }
[[nodiscard]] crypto::Hash256 k_tot_debt_(std::string_view contract_hex) { return key_(contract_hex, "tot_debt"); }
[[nodiscard]] crypto::Hash256 k_last_accrue_height_(std::string_view contract_hex) { return key_(contract_hex, "last_accrue_height"); }

[[nodiscard]] crypto::Hash256 k_shares_(std::string_view contract_hex, std::string_view acct) {
    return crypto::sha256("lend119:shares:" + std::string(contract_hex) + ":" + std::string(acct));
}
[[nodiscard]] crypto::Hash256 k_debt_(std::string_view contract_hex, std::string_view acct) {
    return crypto::sha256("lend119:debt:" + std::string(contract_hex) + ":" + std::string(acct));
}

[[nodiscard]] crypto::Hash256 k_evt_seq_(std::string_view contract_hex) { return key_(contract_hex, "evt_seq"); }
[[nodiscard]] crypto::Hash256 k_evt_n_(std::string_view contract_hex, const std::uint64_t n) {
    return crypto::sha256("lend119:evt:" + std::string(contract_hex) + ":" + std::to_string(n));
}

[[nodiscard]] crypto::Hash256 vault_addr_(std::string_view contract_hex) {
    return crypto::sha256("lend119:vault:" + std::string(contract_hex));
}

[[nodiscard]] crypto::Hash256 rand20_balance_key_(const crypto::Hash256& addr) {
    return crypto::sha256("rand20:bal:" + crypto::to_hex(addr));
}

[[nodiscard]] bool read_storage_u64_(GlobalState& st, const std::string& contract_hex, const crypto::Hash256& key, std::uint64_t& out) {
    const auto v = st.get_contract_storage(contract_hex, key);
    if (!v) {
        out = 0;
        return true;
    }
    const auto dv = decode_u64_(std::span<const std::uint8_t>(v->data(), v->size()));
    if (!dv) {
        return false;
    }
    out = *dv;
    return true;
}

[[nodiscard]] bool read_storage_hash256_(GlobalState& st, const std::string& contract_hex, const crypto::Hash256& key, crypto::Hash256& out) {
    const auto v = st.get_contract_storage(contract_hex, key);
    if (!v || v->size() != 32) {
        return false;
    }
    std::copy(v->begin(), v->end(), out.begin());
    return true;
}

void set_storage_entry_(std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out,
                        const std::string& contract_hex,
                        const crypto::Hash256& key,
                        const std::optional<std::vector<std::uint8_t>>& val) {
    out.emplace_back(contract_hex + ":" + crypto::to_hex(key), val);
}

void set_storage_entry_for_contract_(std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out,
                                     const std::string& target_contract_hex,
                                     const crypto::Hash256& key,
                                     const std::optional<std::vector<std::uint8_t>>& val) {
    out.emplace_back(target_contract_hex + ":" + crypto::to_hex(key), val);
}

[[nodiscard]] bool token_transfer_(GlobalState& st,
                                  const std::string& token_contract_hex,
                                  const crypto::Hash256& from,
                                  const crypto::Hash256& to,
                                  const std::uint64_t amt,
                                  std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
    if (amt == 0) {
        return false;
    }
    std::uint64_t from_bal = 0;
    if (!read_storage_u64_(st, token_contract_hex, rand20_balance_key_(from), from_bal)) {
        return false;
    }
    if (from_bal < amt) {
        return false;
    }
    std::uint64_t to_bal = 0;
    if (!read_storage_u64_(st, token_contract_hex, rand20_balance_key_(to), to_bal)) {
        return false;
    }
    const auto next_to = to_bal + amt;
    if (next_to < to_bal) {
        return false;
    }
    from_bal -= amt;
    set_storage_entry_for_contract_(out_storage_changes, token_contract_hex, rand20_balance_key_(from), encode_u64_(from_bal));
    set_storage_entry_for_contract_(out_storage_changes, token_contract_hex, rand20_balance_key_(to), encode_u64_(next_to));
    return true;
}

[[nodiscard]] bool pow10_u64_(std::uint32_t d, std::uint64_t& out) {
    std::uint64_t v = 1;
    for (std::uint32_t i = 0; i < d; ++i) {
        const auto next = v * 10ULL;
        if (next < v) {
            return false;
        }
        v = next;
    }
    out = v;
    return true;
}

[[nodiscard]] bool get_oracle_price_(GlobalState& st, const std::uint64_t current_height, std::uint64_t& price_num, std::uint64_t& price_den, std::uint64_t& oracle_height) {
    using namespace randio::module117;
    const auto fid = feed_id_from_name("LEND119:USD");
    const auto pp = get_latest(st, fid);
    if (!pp) {
        return false;
    }
    if (current_height < pp->height) {
        return false;
    }
    const auto delta = current_height - pp->height;
    if (delta > kOracleMaxStaleBlocks) {
        return false;
    }
    std::uint64_t den = 0;
    if (!pow10_u64_(pp->decimals, den) || den == 0) {
        return false;
    }
    price_num = pp->value_u64;
    price_den = den;
    oracle_height = pp->height;
    return true;
}

[[nodiscard]] bool health_ok_(const std::uint64_t shares,
                             const std::uint64_t debt,
                             const std::uint64_t ratio_bps,
                             const std::uint64_t price_num,
                             const std::uint64_t price_den) {
    if (debt == 0) {
        return true;
    }
    if (price_den == 0) {
        return false;
    }
    const unsigned __int128 coll_val = (static_cast<unsigned __int128>(shares) * static_cast<unsigned __int128>(price_num)) / static_cast<unsigned __int128>(price_den);
    const unsigned __int128 lhs = coll_val * static_cast<unsigned __int128>(ratio_bps);
    const unsigned __int128 rhs = static_cast<unsigned __int128>(debt) * static_cast<unsigned __int128>(10000);
    return lhs >= rhs;
}

[[nodiscard]] bool load_cfg_(GlobalState& st, const std::string& contract_hex, Config& out) {
    out = Config{};
    std::uint64_t init = 0;
    if (!read_storage_u64_(st, contract_hex, k_cfg_init_(contract_hex), init)) {
        return false;
    }
    out.initialized = (init == 1);
    if (!out.initialized) {
        return true;
    }
    if (!read_storage_hash256_(st, contract_hex, k_cfg_asset_(contract_hex), out.asset_id)) return false;
    if (!read_storage_u64_(st, contract_hex, k_cfg_collateral_factor_bps_(contract_hex), out.collateral_factor_bps)) return false;
    if (!read_storage_u64_(st, contract_hex, k_cfg_liq_threshold_bps_(contract_hex), out.liquidation_threshold_bps)) return false;
    if (!read_storage_u64_(st, contract_hex, k_cfg_interest_bps_(contract_hex), out.interest_rate_bps_per_epoch)) return false;
    if (!read_storage_u64_(st, contract_hex, k_cfg_reserve_bps_(contract_hex), out.reserve_factor_bps)) return false;
    return true;
}

} // namespace

bool lend119_apply(GlobalState& st,
                   const std::string& caller,
                   const std::string& contract_hex,
                   const std::vector<std::uint8_t>& input,
                   const crypto::Hash256&,
                   const std::uint64_t current_height,
                   std::vector<std::pair<std::string, std::optional<Account>>>& out_account_changes,
                   std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
    out_account_changes.clear();
    out_storage_changes.clear();

    if (input.size() < 1) {
        return false;
    }
    const auto op = input[0];

    Config cfg;
    if (!load_cfg_(st, contract_hex, cfg)) {
        return false;
    }

    std::uint64_t evt_seq = 0;
    if (!read_storage_u64_(st, contract_hex, k_evt_seq_(contract_hex), evt_seq)) {
        return false;
    }

    auto next_evt = [&]() -> std::optional<std::uint64_t> {
        const auto next = evt_seq + 1;
        if (next < evt_seq) {
            return std::nullopt;
        }
        evt_seq = next;
        set_storage_entry_(out_storage_changes, contract_hex, k_evt_seq_(contract_hex), encode_u64_(evt_seq));
        return evt_seq;
    };

    auto emit_evt = [&](const std::uint64_t seq, const std::vector<std::uint8_t>& ev) {
        set_storage_entry_(out_storage_changes, contract_hex, k_evt_n_(contract_hex, seq), ev);
    };

    std::optional<std::uint64_t> tot_debt_override;

    auto do_accrue = [&]() -> bool {
        if (!cfg.initialized) {
            return false;
        }
        std::uint64_t last = 0;
        if (!read_storage_u64_(st, contract_hex, k_last_accrue_height_(contract_hex), last)) return false;
        if (current_height < last) {
            return false;
        }
        const auto epochs = current_height - last;
        set_storage_entry_(out_storage_changes, contract_hex, k_last_accrue_height_(contract_hex), encode_u64_(current_height));
        if (epochs == 0 || cfg.interest_rate_bps_per_epoch == 0) {
            return true;
        }
        std::uint64_t tot_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_tot_debt_(contract_hex), tot_debt)) return false;
        if (tot_debt == 0) {
            tot_debt_override = 0;
            return true;
        }
        const unsigned __int128 add = (static_cast<unsigned __int128>(tot_debt) * static_cast<unsigned __int128>(cfg.interest_rate_bps_per_epoch) * static_cast<unsigned __int128>(epochs)) /
                                      static_cast<unsigned __int128>(10000);
        if (add > static_cast<unsigned __int128>((std::numeric_limits<std::uint64_t>::max)())) return false;
        const auto add64 = static_cast<std::uint64_t>(add);
        const auto next = tot_debt + add64;
        if (next < tot_debt) return false;
        set_storage_entry_(out_storage_changes, contract_hex, k_tot_debt_(contract_hex), encode_u64_(next));
        tot_debt_override = next;
        return true;
    };

    if (op == kOpConfigure) {
        if (input.size() != 1 + 32 + 5 * 8) {
            return false;
        }
        std::size_t off = 1;
        const auto asset = read_hash256_at_(std::span<const std::uint8_t>(input.data(), input.size()), off);
        std::uint64_t cf = 0;
        std::uint64_t lt = 0;
        std::uint64_t ir = 0;
        std::uint64_t rf = 0;
        std::uint64_t unused = 0;
        if (!asset) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, cf)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, lt)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, ir)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, rf)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, unused)) return false;
        if (off != input.size()) return false;

        (void)unused;
        if (cf > 10000 || lt > 10000 || ir > 10000 || rf > 10000) {
            return false;
        }
        if (cf > lt) {
            return false;
        }

        set_storage_entry_(out_storage_changes, contract_hex, k_cfg_asset_(contract_hex), std::vector<std::uint8_t>(asset->begin(), asset->end()));
        set_storage_entry_(out_storage_changes, contract_hex, k_cfg_collateral_factor_bps_(contract_hex), encode_u64_(cf));
        set_storage_entry_(out_storage_changes, contract_hex, k_cfg_liq_threshold_bps_(contract_hex), encode_u64_(lt));
        set_storage_entry_(out_storage_changes, contract_hex, k_cfg_interest_bps_(contract_hex), encode_u64_(ir));
        set_storage_entry_(out_storage_changes, contract_hex, k_cfg_reserve_bps_(contract_hex), encode_u64_(rf));
        set_storage_entry_(out_storage_changes, contract_hex, k_cfg_init_(contract_hex), encode_u64_(1));

        set_storage_entry_(out_storage_changes, contract_hex, k_tot_shares_(contract_hex), encode_u64_(0));
        set_storage_entry_(out_storage_changes, contract_hex, k_tot_debt_(contract_hex), encode_u64_(0));
        set_storage_entry_(out_storage_changes, contract_hex, k_last_accrue_height_(contract_hex), encode_u64_(current_height));

        const auto seq = next_evt();
        if (!seq) return false;
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 32 + 4 * 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        ev.insert(ev.end(), asset->begin(), asset->end());
        {
            const auto b = encode_u64_(cf);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        {
            const auto b = encode_u64_(lt);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        {
            const auto b = encode_u64_(ir);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        {
            const auto b = encode_u64_(rf);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        emit_evt(*seq, ev);
        return true;
    }

    if (!cfg.initialized) {
        return false;
    }

    if (op == kOpAccrueInterest) {
        if (input.size() != 1) {
            return false;
        }
        if (!do_accrue()) {
            return false;
        }
        const auto seq = next_evt();
        if (!seq) return false;
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        emit_evt(*seq, ev);
        return true;
    }

    if (!do_accrue()) {
        return false;
    }

    const auto asset_hex = crypto::to_hex(cfg.asset_id);
    const auto caller_addr = crypto::sha256(std::string_view(caller));
    const auto vaddr = vault_addr_(contract_hex);

    if (op == kOpDeposit) {
        if (input.size() != 1 + 8) {
            return false;
        }
        const auto amt = decode_u64_(std::span<const std::uint8_t>(input.data() + 1, 8));
        if (!amt || *amt == 0) {
            return false;
        }
        if (!token_transfer_(st, asset_hex, caller_addr, vaddr, *amt, out_storage_changes)) {
            return false;
        }
        std::uint64_t user_sh = 0;
        if (!read_storage_u64_(st, contract_hex, k_shares_(contract_hex, caller), user_sh)) return false;
        const auto next_user = user_sh + *amt;
        if (next_user < user_sh) return false;
        std::uint64_t tot = 0;
        if (!read_storage_u64_(st, contract_hex, k_tot_shares_(contract_hex), tot)) return false;
        const auto next_tot = tot + *amt;
        if (next_tot < tot) return false;
        set_storage_entry_(out_storage_changes, contract_hex, k_shares_(contract_hex, caller), encode_u64_(next_user));
        set_storage_entry_(out_storage_changes, contract_hex, k_tot_shares_(contract_hex), encode_u64_(next_tot));

        const auto seq = next_evt();
        if (!seq) return false;
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        {
            const auto b = encode_u64_(*amt);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        emit_evt(*seq, ev);
        return true;
    }

    if (op == kOpWithdraw) {
        if (input.size() != 1 + 8) {
            return false;
        }
        const auto sh = decode_u64_(std::span<const std::uint8_t>(input.data() + 1, 8));
        if (!sh || *sh == 0) {
            return false;
        }
        std::uint64_t user_sh = 0;
        std::uint64_t user_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_shares_(contract_hex, caller), user_sh)) return false;
        if (!read_storage_u64_(st, contract_hex, k_debt_(contract_hex, caller), user_debt)) return false;
        if (user_sh < *sh) {
            return false;
        }

        std::uint64_t price_num = 0;
        std::uint64_t price_den = 0;
        std::uint64_t oracle_h = 0;
        if (!get_oracle_price_(st, current_height, price_num, price_den, oracle_h)) {
            return false;
        }
        const auto next_sh = user_sh - *sh;
        if (!health_ok_(next_sh, user_debt, cfg.collateral_factor_bps, price_num, price_den)) {
            return false;
        }

        if (!token_transfer_(st, asset_hex, vaddr, caller_addr, *sh, out_storage_changes)) {
            return false;
        }
        std::uint64_t tot = 0;
        if (!read_storage_u64_(st, contract_hex, k_tot_shares_(contract_hex), tot)) return false;
        if (tot < *sh) return false;
        set_storage_entry_(out_storage_changes, contract_hex, k_shares_(contract_hex, caller), encode_u64_(next_sh));
        set_storage_entry_(out_storage_changes, contract_hex, k_tot_shares_(contract_hex), encode_u64_(tot - *sh));

        const auto seq = next_evt();
        if (!seq) return false;
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        {
            const auto b = encode_u64_(*sh);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        emit_evt(*seq, ev);
        return true;
    }

    if (op == kOpBorrow) {
        if (input.size() != 1 + 8) {
            return false;
        }
        const auto amt = decode_u64_(std::span<const std::uint8_t>(input.data() + 1, 8));
        if (!amt || *amt == 0) {
            return false;
        }
        std::uint64_t user_sh = 0;
        std::uint64_t user_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_shares_(contract_hex, caller), user_sh)) return false;
        if (!read_storage_u64_(st, contract_hex, k_debt_(contract_hex, caller), user_debt)) return false;
        const auto next_debt = user_debt + *amt;
        if (next_debt < user_debt) return false;

        std::uint64_t price_num = 0;
        std::uint64_t price_den = 0;
        std::uint64_t oracle_h = 0;
        if (!get_oracle_price_(st, current_height, price_num, price_den, oracle_h)) {
            return false;
        }
        if (!health_ok_(user_sh, next_debt, cfg.collateral_factor_bps, price_num, price_den)) {
            return false;
        }

        if (!token_transfer_(st, asset_hex, vaddr, caller_addr, *amt, out_storage_changes)) {
            return false;
        }
        std::uint64_t tot_debt = 0;
        if (tot_debt_override.has_value()) {
            tot_debt = *tot_debt_override;
        } else {
            if (!read_storage_u64_(st, contract_hex, k_tot_debt_(contract_hex), tot_debt)) return false;
        }
        const auto next_tot = tot_debt + *amt;
        if (next_tot < tot_debt) return false;
        set_storage_entry_(out_storage_changes, contract_hex, k_debt_(contract_hex, caller), encode_u64_(next_debt));
        set_storage_entry_(out_storage_changes, contract_hex, k_tot_debt_(contract_hex), encode_u64_(next_tot));
        tot_debt_override = next_tot;

        const auto seq = next_evt();
        if (!seq) return false;
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        {
            const auto b = encode_u64_(*amt);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        emit_evt(*seq, ev);
        return true;
    }

    if (op == kOpRepay) {
        if (input.size() != 1 + 8) {
            return false;
        }
        const auto amt = decode_u64_(std::span<const std::uint8_t>(input.data() + 1, 8));
        if (!amt || *amt == 0) {
            return false;
        }
        std::uint64_t user_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_debt_(contract_hex, caller), user_debt)) return false;
        if (user_debt == 0) {
            return false;
        }
        const auto pay = (*amt > user_debt) ? user_debt : *amt;
        if (!token_transfer_(st, asset_hex, caller_addr, vaddr, pay, out_storage_changes)) {
            return false;
        }
        std::uint64_t tot_debt = 0;
        if (tot_debt_override.has_value()) {
            tot_debt = *tot_debt_override;
        } else {
            if (!read_storage_u64_(st, contract_hex, k_tot_debt_(contract_hex), tot_debt)) return false;
        }
        if (tot_debt < pay) return false;
        set_storage_entry_(out_storage_changes, contract_hex, k_debt_(contract_hex, caller), encode_u64_(user_debt - pay));
        set_storage_entry_(out_storage_changes, contract_hex, k_tot_debt_(contract_hex), encode_u64_(tot_debt - pay));
        tot_debt_override = tot_debt - pay;

        const auto seq = next_evt();
        if (!seq) return false;
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        {
            const auto b = encode_u64_(pay);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        emit_evt(*seq, ev);
        return true;
    }

    if (op == kOpLiquidate) {
        std::size_t off = 1;
        std::string victim;
        if (!read_len_string_(std::span<const std::uint8_t>(input.data(), input.size()), off, victim)) {
            return false;
        }
        std::uint64_t repay_amt = 0;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, repay_amt)) {
            return false;
        }
        if (off != input.size() || repay_amt == 0) {
            return false;
        }

        std::uint64_t v_sh = 0;
        std::uint64_t v_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_shares_(contract_hex, victim), v_sh)) return false;
        if (!read_storage_u64_(st, contract_hex, k_debt_(contract_hex, victim), v_debt)) return false;
        if (v_debt == 0 || v_sh == 0) {
            return false;
        }

        std::uint64_t price_num = 0;
        std::uint64_t price_den = 0;
        std::uint64_t oracle_h = 0;
        if (!get_oracle_price_(st, current_height, price_num, price_den, oracle_h)) {
            return false;
        }
        if (health_ok_(v_sh, v_debt, cfg.liquidation_threshold_bps, price_num, price_den)) {
            return false;
        }

        const auto pay = (repay_amt > v_debt) ? v_debt : repay_amt;
        const auto bonus_bps = (cfg.liquidation_threshold_bps >= cfg.collateral_factor_bps) ? (cfg.liquidation_threshold_bps - cfg.collateral_factor_bps) : 0;
        const unsigned __int128 seize_128 = (static_cast<unsigned __int128>(pay) * static_cast<unsigned __int128>(10000 + bonus_bps)) / static_cast<unsigned __int128>(10000);
        if (seize_128 == 0 || seize_128 > static_cast<unsigned __int128>((std::numeric_limits<std::uint64_t>::max)())) {
            return false;
        }
        auto seize = static_cast<std::uint64_t>(seize_128);
        if (seize > v_sh) {
            seize = v_sh;
        }
        if (seize == 0) {
            return false;
        }

        if (!token_transfer_(st, asset_hex, caller_addr, vaddr, pay, out_storage_changes)) {
            return false;
        }

        std::uint64_t liq_sh = 0;
        if (!read_storage_u64_(st, contract_hex, k_shares_(contract_hex, caller), liq_sh)) return false;
        const auto next_liq = liq_sh + seize;
        if (next_liq < liq_sh) return false;

        std::uint64_t tot_debt = 0;
        if (tot_debt_override.has_value()) {
            tot_debt = *tot_debt_override;
        } else {
            if (!read_storage_u64_(st, contract_hex, k_tot_debt_(contract_hex), tot_debt)) return false;
        }
        if (tot_debt < pay) return false;

        set_storage_entry_(out_storage_changes, contract_hex, k_debt_(contract_hex, victim), encode_u64_(v_debt - pay));
        set_storage_entry_(out_storage_changes, contract_hex, k_tot_debt_(contract_hex), encode_u64_(tot_debt - pay));
        tot_debt_override = tot_debt - pay;
        set_storage_entry_(out_storage_changes, contract_hex, k_shares_(contract_hex, victim), encode_u64_(v_sh - seize));
        set_storage_entry_(out_storage_changes, contract_hex, k_shares_(contract_hex, caller), encode_u64_(next_liq));

        const auto seq = next_evt();
        if (!seq) return false;
        const auto victim_addr = crypto::sha256(std::string_view(victim));
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 32 + 8 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        ev.insert(ev.end(), victim_addr.begin(), victim_addr.end());
        {
            const auto b = encode_u64_(pay);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        {
            const auto b = encode_u64_(seize);
            ev.insert(ev.end(), b.begin(), b.end());
        }
        emit_evt(*seq, ev);
        return true;
    }

    return false;
}

} // namespace randio::module119::lend
