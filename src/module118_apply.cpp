#include "rand/module118/apply.hpp"

#include "rand/oracle.hpp"
#include "rand/sha256.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace randio::module118 {
namespace {

constexpr std::uint8_t kOpRegisterParams = 0x10;
constexpr std::uint8_t kOpDeposit = 0x11;
constexpr std::uint8_t kOpWithdraw = 0x12;
constexpr std::uint8_t kOpMint = 0x13;
constexpr std::uint8_t kOpBurn = 0x14;
constexpr std::uint8_t kOpLiquidate = 0x15;

struct Params final {
    std::uint64_t collateral_ratio_bps{0};
    std::uint64_t liquidation_ratio_bps{0};
    std::uint64_t liquidation_penalty_bps{0};
    std::uint64_t debt_ceiling{0};
    std::uint64_t min_deposit{0};
    std::uint64_t min_mint{0};
    std::uint64_t oracle_staleness_blocks{0};
    crypto::Hash256 oracle_feed_id{};
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

[[nodiscard]] std::optional<crypto::Hash256> decode_hash256_(std::span<const std::uint8_t> v) {
    if (v.size() != 32) {
        return std::nullopt;
    }
    crypto::Hash256 out{};
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> encode_u64_(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

[[nodiscard]] crypto::Hash256 owner_key_() {
    return crypto::sha256("owner");
}

[[nodiscard]] crypto::Hash256 key_(std::string_view s) {
    return crypto::sha256(s);
}

[[nodiscard]] crypto::Hash256 k_evt_seq_() {
    return key_("stable118:evt_seq");
}

[[nodiscard]] crypto::Hash256 k_evt_n_(const std::uint64_t n) {
    return crypto::sha256("stable118:evt:" + std::to_string(n));
}

[[nodiscard]] crypto::Hash256 k_total_collateral_() {
    return key_("stable118:total_collateral");
}

[[nodiscard]] crypto::Hash256 k_total_debt_() {
    return key_("stable118:total_debt");
}

[[nodiscard]] crypto::Hash256 k_collateral_(std::string_view acct_id) {
    return crypto::sha256("stable118:collateral:" + std::string(acct_id));
}

[[nodiscard]] crypto::Hash256 k_debt_(std::string_view acct_id) {
    return crypto::sha256("stable118:debt:" + std::string(acct_id));
}

[[nodiscard]] crypto::Hash256 k_bal_(std::string_view acct_id) {
    return crypto::sha256("stable118:bal:" + std::string(acct_id));
}

[[nodiscard]] crypto::Hash256 k_params_collateral_ratio_bps_() {
    return key_("stable118:param:collateral_ratio_bps");
}
[[nodiscard]] crypto::Hash256 k_params_liquidation_ratio_bps_() {
    return key_("stable118:param:liquidation_ratio_bps");
}
[[nodiscard]] crypto::Hash256 k_params_liquidation_penalty_bps_() {
    return key_("stable118:param:liquidation_penalty_bps");
}
[[nodiscard]] crypto::Hash256 k_params_debt_ceiling_() {
    return key_("stable118:param:debt_ceiling");
}
[[nodiscard]] crypto::Hash256 k_params_min_deposit_() {
    return key_("stable118:param:min_deposit");
}
[[nodiscard]] crypto::Hash256 k_params_min_mint_() {
    return key_("stable118:param:min_mint");
}
[[nodiscard]] crypto::Hash256 k_params_oracle_staleness_blocks_() {
    return key_("stable118:param:oracle_staleness_blocks");
}
[[nodiscard]] crypto::Hash256 k_oracle_id_() {
    return key_("stable118:oracle_id");
}
[[nodiscard]] crypto::Hash256 k_last_oracle_height_() {
    return key_("stable118:last_oracle_height");
}
[[nodiscard]] crypto::Hash256 k_params_init_() {
    return key_("stable118:param:initialized");
}

[[nodiscard]] std::string vault_id_(std::string_view contract_hex) {
    return "stable118_vault:" + std::string(contract_hex);
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

[[nodiscard]] std::optional<crypto::Hash256> read_addr32_(std::span<const std::uint8_t> b) {
    if (b.size() != 32) {
        return std::nullopt;
    }
    crypto::Hash256 out{};
    std::copy(b.begin(), b.end(), out.begin());
    return out;
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

[[nodiscard]] bool load_params_(GlobalState& st, const std::string& contract_hex, Params& out) {
    out = Params{};

    std::uint64_t init = 0;
    if (!read_storage_u64_(st, contract_hex, k_params_init_(), init)) {
        return false;
    }
    out.initialized = (init == 1);
    if (!out.initialized) {
        return true;
    }

    if (!read_storage_u64_(st, contract_hex, k_params_collateral_ratio_bps_(), out.collateral_ratio_bps)) return false;
    if (!read_storage_u64_(st, contract_hex, k_params_liquidation_ratio_bps_(), out.liquidation_ratio_bps)) return false;
    if (!read_storage_u64_(st, contract_hex, k_params_liquidation_penalty_bps_(), out.liquidation_penalty_bps)) return false;
    if (!read_storage_u64_(st, contract_hex, k_params_debt_ceiling_(), out.debt_ceiling)) return false;
    if (!read_storage_u64_(st, contract_hex, k_params_min_deposit_(), out.min_deposit)) return false;
    if (!read_storage_u64_(st, contract_hex, k_params_min_mint_(), out.min_mint)) return false;
    if (!read_storage_u64_(st, contract_hex, k_params_oracle_staleness_blocks_(), out.oracle_staleness_blocks)) return false;
    if (!read_storage_hash256_(st, contract_hex, k_oracle_id_(), out.oracle_feed_id)) return false;
    return true;
}

[[nodiscard]] bool get_price_(GlobalState& st,
                             const std::string& contract_hex,
                             const Params& p,
                             const std::uint64_t current_height,
                             std::uint64_t& price_num,
                             std::uint64_t& price_den,
                             std::uint64_t& oracle_height,
                             std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
    using namespace randio::module117;
    if (!p.initialized) {
        return false;
    }
    FeedId fid;
    fid.id = p.oracle_feed_id;
    auto pp = get_latest(st, fid);
    if (!pp) {
        return false;
    }
    if (current_height < pp->height) {
        return false;
    }
    const auto delta = current_height - pp->height;
    if (delta > p.oracle_staleness_blocks) {
        return false;
    }
    std::uint64_t den = 0;
    if (!pow10_u64_(pp->decimals, den) || den == 0) {
        return false;
    }
    price_num = pp->value_u64;
    price_den = den;
    oracle_height = pp->height;

    set_storage_entry_(out_storage_changes, contract_hex, k_last_oracle_height_(), encode_u64_(pp->height));
    return true;
}

[[nodiscard]] bool collateralization_ok_(const std::uint64_t collateral,
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
    const unsigned __int128 col_val = (static_cast<unsigned __int128>(collateral) * static_cast<unsigned __int128>(price_num)) /
                                      static_cast<unsigned __int128>(price_den);
    const unsigned __int128 lhs = col_val * static_cast<unsigned __int128>(10000);
    const unsigned __int128 rhs = static_cast<unsigned __int128>(debt) * static_cast<unsigned __int128>(ratio_bps);
    return lhs >= rhs;
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

} // namespace

bool stable118_apply(GlobalState& st,
                    const std::string& caller,
                    const std::string& contract_hex,
                    const std::vector<std::uint8_t>& input,
                    const std::uint64_t current_height,
                    std::vector<std::pair<std::string, std::optional<Account>>>& out_account_changes,
                    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
    out_account_changes.clear();
    out_storage_changes.clear();

    if (input.size() < 1) {
        return false;
    }

    const auto op = input[0];

    std::uint64_t evt_seq = 0;
    if (!read_storage_u64_(st, contract_hex, k_evt_seq_(), evt_seq)) {
        return false;
    }

    auto next_evt = [&]() -> std::optional<std::uint64_t> {
        const auto next = evt_seq + 1;
        if (next < evt_seq) {
            return std::nullopt;
        }
        evt_seq = next;
        set_storage_entry_(out_storage_changes, contract_hex, k_evt_seq_(), encode_u64_(evt_seq));
        return evt_seq;
    };

    auto emit_evt = [&](const std::uint64_t seq, const std::vector<std::uint8_t>& ev) {
        set_storage_entry_(out_storage_changes, contract_hex, k_evt_n_(seq), ev);
    };

    Params params;
    if (!load_params_(st, contract_hex, params)) {
        return false;
    }

    if (op == kOpRegisterParams) {
        if (input.size() != 1 + 7 * 8 + 32) {
            return false;
        }
        crypto::Hash256 owner{};
        if (!read_storage_hash256_(st, contract_hex, owner_key_(), owner)) {
            return false;
        }
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        if (owner != caller_addr) {
            return false;
        }

        std::size_t off = 1;
        Params p;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, p.collateral_ratio_bps)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, p.liquidation_ratio_bps)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, p.liquidation_penalty_bps)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, p.debt_ceiling)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, p.min_deposit)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, p.min_mint)) return false;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, p.oracle_staleness_blocks)) return false;
        if (off + 32 != input.size()) {
            return false;
        }
        const auto fid = decode_hash256_(std::span<const std::uint8_t>(input.data() + off, 32));
        if (!fid) {
            return false;
        }
        p.oracle_feed_id = *fid;

        if (p.collateral_ratio_bps < 10000 || p.liquidation_ratio_bps < 10000) {
            return false;
        }
        if (p.liquidation_ratio_bps > p.collateral_ratio_bps) {
            return false;
        }
        if (p.liquidation_penalty_bps > 20000) {
            return false;
        }
        p.initialized = true;

        set_storage_entry_(out_storage_changes, contract_hex, k_params_collateral_ratio_bps_(), encode_u64_(p.collateral_ratio_bps));
        set_storage_entry_(out_storage_changes, contract_hex, k_params_liquidation_ratio_bps_(), encode_u64_(p.liquidation_ratio_bps));
        set_storage_entry_(out_storage_changes, contract_hex, k_params_liquidation_penalty_bps_(), encode_u64_(p.liquidation_penalty_bps));
        set_storage_entry_(out_storage_changes, contract_hex, k_params_debt_ceiling_(), encode_u64_(p.debt_ceiling));
        set_storage_entry_(out_storage_changes, contract_hex, k_params_min_deposit_(), encode_u64_(p.min_deposit));
        set_storage_entry_(out_storage_changes, contract_hex, k_params_min_mint_(), encode_u64_(p.min_mint));
        set_storage_entry_(out_storage_changes, contract_hex, k_params_oracle_staleness_blocks_(), encode_u64_(p.oracle_staleness_blocks));
        set_storage_entry_(out_storage_changes, contract_hex, k_oracle_id_(), std::vector<std::uint8_t>(p.oracle_feed_id.begin(), p.oracle_feed_id.end()));
        set_storage_entry_(out_storage_changes, contract_hex, k_params_init_(), encode_u64_(1));

        const auto seq = next_evt();
        if (!seq) {
            return false;
        }
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 7 * 8 + 32);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        ev.insert(ev.end(), input.begin() + 1, input.end());
        emit_evt(*seq, ev);
        return true;
    }

    if (!params.initialized) {
        return false;
    }

    if (op == kOpDeposit) {
        if (input.size() != 1 + 8) {
            return false;
        }
        const auto amt = decode_u64_(std::span<const std::uint8_t>(input.data() + 1, 8));
        if (!amt || *amt == 0 || *amt < params.min_deposit) {
            return false;
        }

        const auto user = st.get_account(caller);
        if (!user || user->balance < *amt) {
            return false;
        }
        const auto vault_id = vault_id_(contract_hex);
        const auto vault = st.get_account(vault_id).value_or(Account{});

        Account user_next = *user;
        user_next.balance -= *amt;
        Account vault_next = vault;
        const auto next_vault_bal = vault_next.balance + *amt;
        if (next_vault_bal < vault_next.balance) {
            return false;
        }
        vault_next.balance = next_vault_bal;
        out_account_changes.emplace_back(caller, user_next);
        out_account_changes.emplace_back(vault_id, vault_next);

        std::uint64_t cur_coll = 0;
        if (!read_storage_u64_(st, contract_hex, k_collateral_(caller), cur_coll)) {
            return false;
        }
        const auto next_coll = cur_coll + *amt;
        if (next_coll < cur_coll) {
            return false;
        }
        set_storage_entry_(out_storage_changes, contract_hex, k_collateral_(caller), encode_u64_(next_coll));

        std::uint64_t tot = 0;
        if (!read_storage_u64_(st, contract_hex, k_total_collateral_(), tot)) {
            return false;
        }
        const auto next_tot = tot + *amt;
        if (next_tot < tot) {
            return false;
        }
        set_storage_entry_(out_storage_changes, contract_hex, k_total_collateral_(), encode_u64_(next_tot));

        const auto seq = next_evt();
        if (!seq) {
            return false;
        }
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        const auto ab = encode_u64_(*amt);
        ev.insert(ev.end(), ab.begin(), ab.end());
        emit_evt(*seq, ev);
        return true;
    }

    if (op == kOpWithdraw) {
        if (input.size() != 1 + 8) {
            return false;
        }
        const auto amt = decode_u64_(std::span<const std::uint8_t>(input.data() + 1, 8));
        if (!amt || *amt == 0) {
            return false;
        }

        std::uint64_t price_num = 0;
        std::uint64_t price_den = 0;
        std::uint64_t oracle_h = 0;
        if (!get_price_(st, contract_hex, params, current_height, price_num, price_den, oracle_h, out_storage_changes)) {
            return false;
        }

        std::uint64_t cur_coll = 0;
        std::uint64_t cur_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_collateral_(caller), cur_coll)) return false;
        if (!read_storage_u64_(st, contract_hex, k_debt_(caller), cur_debt)) return false;
        if (cur_coll < *amt) {
            return false;
        }
        const auto next_coll = cur_coll - *amt;
        if (!collateralization_ok_(next_coll, cur_debt, params.collateral_ratio_bps, price_num, price_den)) {
            return false;
        }

        const auto vault_id = vault_id_(contract_hex);
        const auto vault = st.get_account(vault_id);
        const auto user = st.get_account(caller);
        if (!vault || !user) {
            return false;
        }
        if (vault->balance < *amt) {
            return false;
        }
        Account vault_next = *vault;
        vault_next.balance -= *amt;
        Account user_next = *user;
        const auto nb = user_next.balance + *amt;
        if (nb < user_next.balance) {
            return false;
        }
        user_next.balance = nb;
        out_account_changes.emplace_back(vault_id, vault_next);
        out_account_changes.emplace_back(caller, user_next);

        set_storage_entry_(out_storage_changes, contract_hex, k_collateral_(caller), encode_u64_(next_coll));

        std::uint64_t tot = 0;
        if (!read_storage_u64_(st, contract_hex, k_total_collateral_(), tot)) return false;
        if (tot < *amt) return false;
        set_storage_entry_(out_storage_changes, contract_hex, k_total_collateral_(), encode_u64_(tot - *amt));

        const auto seq = next_evt();
        if (!seq) return false;
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        const auto ab = encode_u64_(*amt);
        ev.insert(ev.end(), ab.begin(), ab.end());
        emit_evt(*seq, ev);
        return true;
    }

    if (op == kOpMint) {
        if (input.size() != 1 + 8) {
            return false;
        }
        const auto amt = decode_u64_(std::span<const std::uint8_t>(input.data() + 1, 8));
        if (!amt || *amt == 0 || *amt < params.min_mint) {
            return false;
        }

        std::uint64_t price_num = 0;
        std::uint64_t price_den = 0;
        std::uint64_t oracle_h = 0;
        if (!get_price_(st, contract_hex, params, current_height, price_num, price_den, oracle_h, out_storage_changes)) {
            return false;
        }

        std::uint64_t cur_coll = 0;
        std::uint64_t cur_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_collateral_(caller), cur_coll)) return false;
        if (!read_storage_u64_(st, contract_hex, k_debt_(caller), cur_debt)) return false;
        const auto next_debt = cur_debt + *amt;
        if (next_debt < cur_debt) {
            return false;
        }

        std::uint64_t tot_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_total_debt_(), tot_debt)) return false;
        const auto next_tot = tot_debt + *amt;
        if (next_tot < tot_debt) return false;
        if (next_tot > params.debt_ceiling) {
            return false;
        }
        if (!collateralization_ok_(cur_coll, next_debt, params.collateral_ratio_bps, price_num, price_den)) {
            return false;
        }

        std::uint64_t bal = 0;
        if (!read_storage_u64_(st, contract_hex, k_bal_(caller), bal)) return false;
        const auto next_bal = bal + *amt;
        if (next_bal < bal) return false;

        set_storage_entry_(out_storage_changes, contract_hex, k_debt_(caller), encode_u64_(next_debt));
        set_storage_entry_(out_storage_changes, contract_hex, k_total_debt_(), encode_u64_(next_tot));
        set_storage_entry_(out_storage_changes, contract_hex, k_bal_(caller), encode_u64_(next_bal));

        const auto seq = next_evt();
        if (!seq) return false;
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        const auto ab = encode_u64_(*amt);
        ev.insert(ev.end(), ab.begin(), ab.end());
        emit_evt(*seq, ev);
        return true;
    }

    if (op == kOpBurn) {
        if (input.size() != 1 + 8) {
            return false;
        }
        const auto amt = decode_u64_(std::span<const std::uint8_t>(input.data() + 1, 8));
        if (!amt || *amt == 0) {
            return false;
        }
        std::uint64_t bal = 0;
        std::uint64_t debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_bal_(caller), bal)) return false;
        if (!read_storage_u64_(st, contract_hex, k_debt_(caller), debt)) return false;
        if (bal < *amt || debt < *amt) {
            return false;
        }

        std::uint64_t tot_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_total_debt_(), tot_debt)) return false;
        if (tot_debt < *amt) return false;

        set_storage_entry_(out_storage_changes, contract_hex, k_bal_(caller), encode_u64_(bal - *amt));
        set_storage_entry_(out_storage_changes, contract_hex, k_debt_(caller), encode_u64_(debt - *amt));
        set_storage_entry_(out_storage_changes, contract_hex, k_total_debt_(), encode_u64_(tot_debt - *amt));

        const auto seq = next_evt();
        if (!seq) return false;
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        const auto ab = encode_u64_(*amt);
        ev.insert(ev.end(), ab.begin(), ab.end());
        emit_evt(*seq, ev);
        return true;
    }

    if (op == kOpLiquidate) {
        std::size_t off = 1;
        std::string target;
        if (!read_len_string_(std::span<const std::uint8_t>(input.data(), input.size()), off, target)) {
            return false;
        }
        std::uint64_t burn_amt = 0;
        if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, burn_amt)) {
            return false;
        }
        if (off != input.size() || burn_amt == 0) {
            return false;
        }

        std::uint64_t price_num = 0;
        std::uint64_t price_den = 0;
        std::uint64_t oracle_h = 0;
        if (!get_price_(st, contract_hex, params, current_height, price_num, price_den, oracle_h, out_storage_changes)) {
            return false;
        }

        std::uint64_t t_coll = 0;
        std::uint64_t t_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_collateral_(target), t_coll)) return false;
        if (!read_storage_u64_(st, contract_hex, k_debt_(target), t_debt)) return false;
        if (t_debt == 0) {
            return false;
        }
        if (collateralization_ok_(t_coll, t_debt, params.liquidation_ratio_bps, price_num, price_den)) {
            return false;
        }
        if (burn_amt > t_debt) {
            burn_amt = t_debt;
        }

        std::uint64_t liq_bal = 0;
        if (!read_storage_u64_(st, contract_hex, k_bal_(caller), liq_bal)) return false;
        if (liq_bal < burn_amt) {
            return false;
        }

        std::uint64_t tot_debt = 0;
        if (!read_storage_u64_(st, contract_hex, k_total_debt_(), tot_debt)) return false;
        if (tot_debt < burn_amt) return false;

        const unsigned __int128 base_coll = (static_cast<unsigned __int128>(burn_amt) * static_cast<unsigned __int128>(price_den) + static_cast<unsigned __int128>(price_num) - 1u) /
                                            static_cast<unsigned __int128>(price_num);
        const unsigned __int128 reward_coll = (base_coll * static_cast<unsigned __int128>(10000 + params.liquidation_penalty_bps)) / static_cast<unsigned __int128>(10000);
        std::uint64_t reward = 0;
        if (reward_coll > static_cast<unsigned __int128>((std::numeric_limits<std::uint64_t>::max)())) {
            return false;
        }
        reward = static_cast<std::uint64_t>(reward_coll);
        if (reward > t_coll) {
            reward = t_coll;
        }
        if (reward == 0) {
            return false;
        }

        const auto vault_id = vault_id_(contract_hex);
        const auto vault = st.get_account(vault_id);
        const auto liq_acc = st.get_account(caller);
        if (!vault || !liq_acc) {
            return false;
        }
        if (vault->balance < reward) {
            return false;
        }
        Account vault_next = *vault;
        vault_next.balance -= reward;
        Account liq_next = *liq_acc;
        const auto next_liq_bal = liq_next.balance + reward;
        if (next_liq_bal < liq_next.balance) {
            return false;
        }
        liq_next.balance = next_liq_bal;
        out_account_changes.emplace_back(vault_id, vault_next);
        out_account_changes.emplace_back(caller, liq_next);

        set_storage_entry_(out_storage_changes, contract_hex, k_bal_(caller), encode_u64_(liq_bal - burn_amt));
        set_storage_entry_(out_storage_changes, contract_hex, k_debt_(target), encode_u64_(t_debt - burn_amt));
        set_storage_entry_(out_storage_changes, contract_hex, k_total_debt_(), encode_u64_(tot_debt - burn_amt));

        set_storage_entry_(out_storage_changes, contract_hex, k_collateral_(target), encode_u64_(t_coll - reward));
        std::uint64_t tot_coll = 0;
        if (!read_storage_u64_(st, contract_hex, k_total_collateral_(), tot_coll)) return false;
        if (tot_coll < reward) return false;
        set_storage_entry_(out_storage_changes, contract_hex, k_total_collateral_(), encode_u64_(tot_coll - reward));

        const auto seq = next_evt();
        if (!seq) return false;
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        const auto target_addr = crypto::sha256(std::string_view(target));
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 32 + 8 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        ev.insert(ev.end(), target_addr.begin(), target_addr.end());
        {
            const auto bb = encode_u64_(burn_amt);
            ev.insert(ev.end(), bb.begin(), bb.end());
        }
        {
            const auto rb = encode_u64_(reward);
            ev.insert(ev.end(), rb.begin(), rb.end());
        }
        emit_evt(*seq, ev);
        return true;
    }

    return false;
}

} // namespace randio::module118
