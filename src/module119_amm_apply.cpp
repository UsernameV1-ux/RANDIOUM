#include "rand/module119/amm/apply.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace randio::module119::amm {
namespace {

constexpr std::uint8_t kOpCreatePool = 0x01;
constexpr std::uint8_t kOpAddLiquidity = 0x02;
constexpr std::uint8_t kOpRemoveLiquidity = 0x03;
constexpr std::uint8_t kOpSwapExactIn = 0x04;

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

[[nodiscard]] std::optional<crypto::Hash256> read_addr32_at_(std::span<const std::uint8_t> b, std::size_t& off) {
    if (off + 32 > b.size()) {
        return std::nullopt;
    }
    crypto::Hash256 out{};
    std::copy(b.begin() + static_cast<std::ptrdiff_t>(off), b.begin() + static_cast<std::ptrdiff_t>(off + 32), out.begin());
    off += 32;
    return out;
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

[[nodiscard]] crypto::Hash256 k_token0_() {
    return crypto::sha256("amm119:token0");
}
[[nodiscard]] crypto::Hash256 k_token1_() {
    return crypto::sha256("amm119:token1");
}
[[nodiscard]] crypto::Hash256 k_r0_() {
    return crypto::sha256("amm119:r0");
}
[[nodiscard]] crypto::Hash256 k_r1_() {
    return crypto::sha256("amm119:r1");
}
[[nodiscard]] crypto::Hash256 k_lp_supply_() {
    return crypto::sha256("amm119:lp_supply");
}
[[nodiscard]] crypto::Hash256 k_fee_bps_() {
    return crypto::sha256("amm119:fee_bps");
}
[[nodiscard]] crypto::Hash256 k_lp_bal_(std::string_view acct_id) {
    return crypto::sha256("amm119:lp:" + std::string(acct_id));
}
[[nodiscard]] crypto::Hash256 k_evt_seq_() {
    return crypto::sha256("amm119:evt_seq");
}
[[nodiscard]] crypto::Hash256 k_evt_n_(const std::uint64_t n) {
    return crypto::sha256("amm119:evt:" + std::to_string(n));
}

[[nodiscard]] crypto::Hash256 rand20_balance_key_(const crypto::Hash256& addr) {
    return crypto::sha256("rand20:bal:" + crypto::to_hex(addr));
}

[[nodiscard]] crypto::Hash256 pool_addr_(std::string_view contract_hex) {
    return crypto::sha256("amm119:pool:" + std::string(contract_hex));
}

void set_storage_entry_for_contract_(std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out,
                                     const std::string& target_contract_hex,
                                     const crypto::Hash256& key,
                                     const std::optional<std::vector<std::uint8_t>>& val) {
    out.emplace_back(target_contract_hex + ":" + crypto::to_hex(key), val);
}

[[nodiscard]] std::optional<std::uint64_t> isqrt_u128_(const unsigned __int128 x) {
    if (x == 0) {
        return 0;
    }
    unsigned __int128 r = x;
    unsigned __int128 prev = 0;
    while (r != prev) {
        prev = r;
        r = (r + x / r) / 2;
    }
    if (r > static_cast<unsigned __int128>((std::numeric_limits<std::uint64_t>::max)())) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(r);
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

} // namespace

bool amm119_apply(GlobalState& st,
                  const std::string& caller,
                  const std::string& contract_hex,
                  const std::vector<std::uint8_t>& input,
                  const crypto::Hash256&,
                  std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
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

    crypto::Hash256 token0{};
    crypto::Hash256 token1{};
    const bool initialized = read_storage_hash256_(st, contract_hex, k_token0_(), token0) &&
                             read_storage_hash256_(st, contract_hex, k_token1_(), token1);

    if (op == kOpCreatePool) {
        if (initialized) {
            return false;
        }
        if (input.size() != 1 + 32 + 32 + 8) {
            return false;
        }
        std::size_t off = 1;
        const auto t0 = read_addr32_at_(std::span<const std::uint8_t>(input.data(), input.size()), off);
        const auto t1 = read_addr32_at_(std::span<const std::uint8_t>(input.data(), input.size()), off);
        std::uint64_t fee_bps = 0;
        if (!t0 || !t1 || !read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, fee_bps) || off != input.size()) {
            return false;
        }
        if (*t0 == *t1) {
            return false;
        }
        if (fee_bps > 10000) {
            return false;
        }

        set_storage_entry_(out_storage_changes, contract_hex, k_token0_(), std::vector<std::uint8_t>(t0->begin(), t0->end()));
        set_storage_entry_(out_storage_changes, contract_hex, k_token1_(), std::vector<std::uint8_t>(t1->begin(), t1->end()));
        set_storage_entry_(out_storage_changes, contract_hex, k_r0_(), encode_u64_(0));
        set_storage_entry_(out_storage_changes, contract_hex, k_r1_(), encode_u64_(0));
        set_storage_entry_(out_storage_changes, contract_hex, k_lp_supply_(), encode_u64_(0));
        set_storage_entry_(out_storage_changes, contract_hex, k_fee_bps_(), encode_u64_(fee_bps));

        const auto seq = next_evt();
        if (!seq) {
            return false;
        }
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 32 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        ev.insert(ev.end(), t0->begin(), t0->end());
        ev.insert(ev.end(), t1->begin(), t1->end());
        {
            const auto fb = encode_u64_(fee_bps);
            ev.insert(ev.end(), fb.begin(), fb.end());
        }
        emit_evt(*seq, ev);
        return true;
    }

    if (!initialized) {
        return false;
    }

    if (op == kOpAddLiquidity || op == kOpRemoveLiquidity || op == kOpSwapExactIn) {
        std::uint64_t r0 = 0;
        std::uint64_t r1 = 0;
        std::uint64_t lp_supply = 0;
        std::uint64_t fee_bps = 0;
        if (!read_storage_u64_(st, contract_hex, k_r0_(), r0)) return false;
        if (!read_storage_u64_(st, contract_hex, k_r1_(), r1)) return false;
        if (!read_storage_u64_(st, contract_hex, k_lp_supply_(), lp_supply)) return false;
        if (!read_storage_u64_(st, contract_hex, k_fee_bps_(), fee_bps)) return false;

        const auto token0_hex = crypto::to_hex(token0);
        const auto token1_hex = crypto::to_hex(token1);
        const auto caller_addr = crypto::sha256(std::string_view(caller));
        const auto pool_addr = pool_addr_(contract_hex);

        if (op == kOpAddLiquidity) {
            if (input.size() != 1 + 8 + 8 + 8) {
                return false;
            }
            std::size_t off = 1;
            std::uint64_t amt0 = 0;
            std::uint64_t amt1 = 0;
            std::uint64_t min_lp = 0;
            if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, amt0)) return false;
            if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, amt1)) return false;
            if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, min_lp)) return false;
            if (off != input.size() || amt0 == 0 || amt1 == 0) {
                return false;
            }

            std::uint64_t lp_minted = 0;
            if (lp_supply == 0) {
                const unsigned __int128 prod = static_cast<unsigned __int128>(amt0) * static_cast<unsigned __int128>(amt1);
                const auto s = isqrt_u128_(prod);
                if (!s || *s == 0) {
                    return false;
                }
                lp_minted = *s;
            } else {
                if (r0 == 0 || r1 == 0) {
                    return false;
                }
                const unsigned __int128 a = (static_cast<unsigned __int128>(amt0) * static_cast<unsigned __int128>(lp_supply)) / static_cast<unsigned __int128>(r0);
                const unsigned __int128 b = (static_cast<unsigned __int128>(amt1) * static_cast<unsigned __int128>(lp_supply)) / static_cast<unsigned __int128>(r1);
                const unsigned __int128 m = (a < b) ? a : b;
                if (m == 0 || m > static_cast<unsigned __int128>((std::numeric_limits<std::uint64_t>::max)())) {
                    return false;
                }
                lp_minted = static_cast<std::uint64_t>(m);
            }
            if (lp_minted < min_lp) {
                return false;
            }

            if (!token_transfer_(st, token0_hex, caller_addr, pool_addr, amt0, out_storage_changes)) return false;
            if (!token_transfer_(st, token1_hex, caller_addr, pool_addr, amt1, out_storage_changes)) return false;

            const auto nr0 = r0 + amt0;
            if (nr0 < r0) return false;
            const auto nr1 = r1 + amt1;
            if (nr1 < r1) return false;
            const auto nlp = lp_supply + lp_minted;
            if (nlp < lp_supply) return false;

            std::uint64_t cur_lp = 0;
            if (!read_storage_u64_(st, contract_hex, k_lp_bal_(caller), cur_lp)) return false;
            const auto next_lp = cur_lp + lp_minted;
            if (next_lp < cur_lp) return false;

            set_storage_entry_(out_storage_changes, contract_hex, k_r0_(), encode_u64_(nr0));
            set_storage_entry_(out_storage_changes, contract_hex, k_r1_(), encode_u64_(nr1));
            set_storage_entry_(out_storage_changes, contract_hex, k_lp_supply_(), encode_u64_(nlp));
            set_storage_entry_(out_storage_changes, contract_hex, k_lp_bal_(caller), encode_u64_(next_lp));

            const auto seq = next_evt();
            if (!seq) return false;
            std::vector<std::uint8_t> ev;
            ev.reserve(1 + 32 + 8 + 8 + 8);
            ev.push_back(op);
            ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
            {
                const auto b = encode_u64_(amt0);
                ev.insert(ev.end(), b.begin(), b.end());
            }
            {
                const auto b = encode_u64_(amt1);
                ev.insert(ev.end(), b.begin(), b.end());
            }
            {
                const auto b = encode_u64_(lp_minted);
                ev.insert(ev.end(), b.begin(), b.end());
            }
            emit_evt(*seq, ev);
            return true;
        }

        if (op == kOpRemoveLiquidity) {
            if (input.size() != 1 + 8 + 8 + 8) {
                return false;
            }
            if (lp_supply == 0 || r0 == 0 || r1 == 0) {
                return false;
            }
            std::size_t off = 1;
            std::uint64_t lp_amt = 0;
            std::uint64_t min0 = 0;
            std::uint64_t min1 = 0;
            if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, lp_amt)) return false;
            if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, min0)) return false;
            if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, min1)) return false;
            if (off != input.size() || lp_amt == 0) {
                return false;
            }

            std::uint64_t user_lp = 0;
            if (!read_storage_u64_(st, contract_hex, k_lp_bal_(caller), user_lp)) return false;
            if (user_lp < lp_amt) return false;

            const unsigned __int128 out0_128 = (static_cast<unsigned __int128>(lp_amt) * static_cast<unsigned __int128>(r0)) / static_cast<unsigned __int128>(lp_supply);
            const unsigned __int128 out1_128 = (static_cast<unsigned __int128>(lp_amt) * static_cast<unsigned __int128>(r1)) / static_cast<unsigned __int128>(lp_supply);
            if (out0_128 == 0 || out1_128 == 0) return false;
            if (out0_128 > static_cast<unsigned __int128>((std::numeric_limits<std::uint64_t>::max)())) return false;
            if (out1_128 > static_cast<unsigned __int128>((std::numeric_limits<std::uint64_t>::max)())) return false;
            const auto out0 = static_cast<std::uint64_t>(out0_128);
            const auto out1 = static_cast<std::uint64_t>(out1_128);
            if (out0 < min0 || out1 < min1) return false;
            if (r0 < out0 || r1 < out1) return false;

            if (!token_transfer_(st, token0_hex, pool_addr, caller_addr, out0, out_storage_changes)) return false;
            if (!token_transfer_(st, token1_hex, pool_addr, caller_addr, out1, out_storage_changes)) return false;

            set_storage_entry_(out_storage_changes, contract_hex, k_r0_(), encode_u64_(r0 - out0));
            set_storage_entry_(out_storage_changes, contract_hex, k_r1_(), encode_u64_(r1 - out1));
            set_storage_entry_(out_storage_changes, contract_hex, k_lp_supply_(), encode_u64_(lp_supply - lp_amt));
            set_storage_entry_(out_storage_changes, contract_hex, k_lp_bal_(caller), encode_u64_(user_lp - lp_amt));

            const auto seq = next_evt();
            if (!seq) return false;
            std::vector<std::uint8_t> ev;
            ev.reserve(1 + 32 + 8 + 8 + 8);
            ev.push_back(op);
            ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
            {
                const auto b = encode_u64_(lp_amt);
                ev.insert(ev.end(), b.begin(), b.end());
            }
            {
                const auto b = encode_u64_(out0);
                ev.insert(ev.end(), b.begin(), b.end());
            }
            {
                const auto b = encode_u64_(out1);
                ev.insert(ev.end(), b.begin(), b.end());
            }
            emit_evt(*seq, ev);
            return true;
        }

        if (op == kOpSwapExactIn) {
            if (input.size() != 1 + 8 + 8 + 8) {
                return false;
            }
            if (r0 == 0 || r1 == 0 || fee_bps > 10000) {
                return false;
            }
            std::size_t off = 1;
            std::uint64_t dir = 0;
            std::uint64_t amt_in = 0;
            std::uint64_t min_out = 0;
            if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, dir)) return false;
            if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, amt_in)) return false;
            if (!read_u64_at_(std::span<const std::uint8_t>(input.data(), input.size()), off, min_out)) return false;
            if (off != input.size() || amt_in == 0 || (dir != 0 && dir != 1)) {
                return false;
            }

            const auto fee_mul = static_cast<unsigned __int128>(10000 - fee_bps);
            const unsigned __int128 in_after_fee_128 = (static_cast<unsigned __int128>(amt_in) * fee_mul) / static_cast<unsigned __int128>(10000);
            if (in_after_fee_128 == 0 || in_after_fee_128 > static_cast<unsigned __int128>((std::numeric_limits<std::uint64_t>::max)())) {
                return false;
            }
            const auto in_af = static_cast<std::uint64_t>(in_after_fee_128);

            const bool zero_to_one = (dir == 0);
            const auto rin = zero_to_one ? r0 : r1;
            const auto rout = zero_to_one ? r1 : r0;

            const unsigned __int128 num = static_cast<unsigned __int128>(in_af) * static_cast<unsigned __int128>(rout);
            const unsigned __int128 den = static_cast<unsigned __int128>(rin) + static_cast<unsigned __int128>(in_af);
            if (den == 0) return false;
            const unsigned __int128 out_128 = num / den;
            if (out_128 == 0 || out_128 > static_cast<unsigned __int128>((std::numeric_limits<std::uint64_t>::max)())) return false;
            const auto amt_out = static_cast<std::uint64_t>(out_128);
            if (amt_out < min_out) return false;
            if (amt_out >= rout) return false;

            if (zero_to_one) {
                if (!token_transfer_(st, token0_hex, caller_addr, pool_addr, amt_in, out_storage_changes)) return false;
                if (!token_transfer_(st, token1_hex, pool_addr, caller_addr, amt_out, out_storage_changes)) return false;
                const auto nr0 = r0 + amt_in;
                if (nr0 < r0) return false;
                if (r1 < amt_out) return false;
                set_storage_entry_(out_storage_changes, contract_hex, k_r0_(), encode_u64_(nr0));
                set_storage_entry_(out_storage_changes, contract_hex, k_r1_(), encode_u64_(r1 - amt_out));
            } else {
                if (!token_transfer_(st, token1_hex, caller_addr, pool_addr, amt_in, out_storage_changes)) return false;
                if (!token_transfer_(st, token0_hex, pool_addr, caller_addr, amt_out, out_storage_changes)) return false;
                const auto nr1 = r1 + amt_in;
                if (nr1 < r1) return false;
                if (r0 < amt_out) return false;
                set_storage_entry_(out_storage_changes, contract_hex, k_r1_(), encode_u64_(nr1));
                set_storage_entry_(out_storage_changes, contract_hex, k_r0_(), encode_u64_(r0 - amt_out));
            }

            const auto seq = next_evt();
            if (!seq) return false;
            std::vector<std::uint8_t> ev;
            ev.reserve(1 + 32 + 8 + 8 + 8);
            ev.push_back(op);
            ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
            {
                const auto b = encode_u64_(dir);
                ev.insert(ev.end(), b.begin(), b.end());
            }
            {
                const auto b = encode_u64_(amt_in);
                ev.insert(ev.end(), b.begin(), b.end());
            }
            {
                const auto b = encode_u64_(amt_out);
                ev.insert(ev.end(), b.begin(), b.end());
            }
            emit_evt(*seq, ev);
            return true;
        }

        return false;
    }

    return false;
}

} // namespace randio::module119::amm
