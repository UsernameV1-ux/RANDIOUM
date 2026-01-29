#include "rand/wrap/apply.hpp"

#include "rand/state.hpp"
#include "rand/wrap/contract.hpp"

#include <array>
#include <string>

namespace randio::module116 {
namespace {

[[nodiscard]] std::vector<std::uint8_t> encode_u64_le_(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

[[nodiscard]] bool decode_u64_le_(const std::optional<std::vector<std::uint8_t>>& v, std::uint64_t& out) {
    if (!v) {
        out = 0;
        return true;
    }
    if (v->size() != 8) {
        return false;
    }
    std::uint64_t x = 0;
    for (int i = 0; i < 8; ++i) {
        x |= (static_cast<std::uint64_t>((*v)[static_cast<std::size_t>(i)]) << (8u * i));
    }
    out = x;
    return true;
}

[[nodiscard]] std::string wrap_asset_entry_(const WrappedAssetId& id) {
    return "wrap:asset:" + crypto::to_hex(id.id);
}

[[nodiscard]] std::string wrap_minted_entry_(const WrappedAssetId& id) {
    return "wrap:supply_minted:" + crypto::to_hex(id.id);
}

[[nodiscard]] std::string wrap_burned_entry_(const WrappedAssetId& id) {
    return "wrap:supply_burned:" + crypto::to_hex(id.id);
}

[[nodiscard]] std::string bridge_seen_entry_(const crypto::Hash256& msg_id) {
    return "bridge:seen:" + crypto::to_hex(msg_id);
}

[[nodiscard]] crypto::Hash256 wrap_contract_address_(const WrappedAssetId& id) {
    return wrap116_contract_address(id);
}

[[nodiscard]] bool asset_ok_(const GlobalState& st, const WrappedAssetId& id) {
    const auto ai = st.wrap_get_asset(id);
    if (!ai) {
        return false;
    }
    return ai->status == module116::AssetStatus::Active;
}

[[nodiscard]] bool ensure_wrap_contract_(GlobalState& st, const WrappedAssetId& asset, StateDelta& out_delta) {
    out_delta = StateDelta{};
    const auto c = wrap_contract_address_(asset);
    const auto ch = crypto::to_hex(c);

    const auto cur_code = st.get_contract_code(ch);
    if (cur_code) {
        if (!is_wrap116_contract(*cur_code)) {
            return false;
        }
        return true;
    }

    const auto code = wrap116_marker_code();
    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> code_changes;
    code_changes.emplace_back(ch, code);

    const auto asset_key = crypto::sha256("wrap116:asset_id");
    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    std::vector<std::uint8_t> idv(asset.id.begin(), asset.id.end());
    storage_changes.emplace_back(ch + ":" + crypto::to_hex(asset_key), idv);

    const auto seq_key = wrap116_evt_seq_key();
    storage_changes.emplace_back(ch + ":" + crypto::to_hex(seq_key), encode_u64_le_(0));

    return st.apply_batch({}, code_changes, storage_changes, out_delta);
}

[[nodiscard]] bool build_mint_changes_(GlobalState& st,
                                     const WrappedAssetId& asset,
                                     const crypto::Hash256& to,
                                     const std::uint64_t amount,
                                     std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
    if (amount == 0) {
        return false;
    }

    const auto c = wrap_contract_address_(asset);
    const auto ch = crypto::to_hex(c);

    const auto code = st.get_contract_code(ch);
    if (!code || !is_wrap116_contract(*code)) {
        return false;
    }

    std::uint64_t minted = 0;
    if (!decode_u64_le_(st.get_storage_entry(wrap_minted_entry_(asset)), minted)) {
        return false;
    }
    std::uint64_t burned = 0;
    if (!decode_u64_le_(st.get_storage_entry(wrap_burned_entry_(asset)), burned)) {
        return false;
    }

    const auto next_minted = minted + amount;
    if (next_minted < minted) {
        return false;
    }

    std::uint64_t to_bal = 0;
    if (!decode_u64_le_(st.get_contract_storage(ch, wrap116_balance_key(to)), to_bal)) {
        return false;
    }
    const auto next_to = to_bal + amount;
    if (next_to < to_bal) {
        return false;
    }

    std::uint64_t evt_seq = 0;
    if (!decode_u64_le_(st.get_contract_storage(ch, wrap116_evt_seq_key()), evt_seq)) {
        return false;
    }
    const auto seq = evt_seq + 1;
    if (seq < evt_seq) {
        return false;
    }

    out_storage_changes.emplace_back(wrap_minted_entry_(asset), encode_u64_le_(next_minted));

    out_storage_changes.emplace_back(ch + ":" + crypto::to_hex(wrap116_balance_key(to)), encode_u64_le_(next_to));
    out_storage_changes.emplace_back(ch + ":" + crypto::to_hex(wrap116_evt_seq_key()), encode_u64_le_(seq));

    std::vector<std::uint8_t> ev;
    ev.reserve(1 + 32 + 32 + 8);
    ev.push_back(0x02);
    ev.insert(ev.end(), crypto::Hash256{}.begin(), crypto::Hash256{}.end());
    ev.insert(ev.end(), to.begin(), to.end());
    const auto ab = encode_u64_le_(amount);
    ev.insert(ev.end(), ab.begin(), ab.end());
    out_storage_changes.emplace_back(ch + ":" + crypto::to_hex(wrap116_evt_key(seq)), ev);

    (void)burned;
    return true;
}

[[nodiscard]] bool build_burn_changes_(GlobalState& st,
                                     const WrappedAssetId& asset,
                                     const crypto::Hash256& from,
                                     const std::uint64_t amount,
                                     std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
    if (amount == 0) {
        return false;
    }

    const auto c = wrap_contract_address_(asset);
    const auto ch = crypto::to_hex(c);

    const auto code = st.get_contract_code(ch);
    if (!code || !is_wrap116_contract(*code)) {
        return false;
    }

    std::uint64_t minted = 0;
    if (!decode_u64_le_(st.get_storage_entry(wrap_minted_entry_(asset)), minted)) {
        return false;
    }
    std::uint64_t burned = 0;
    if (!decode_u64_le_(st.get_storage_entry(wrap_burned_entry_(asset)), burned)) {
        return false;
    }

    const auto next_burned = burned + amount;
    if (next_burned < burned) {
        return false;
    }
    if (next_burned > minted) {
        return false;
    }

    std::uint64_t from_bal = 0;
    if (!decode_u64_le_(st.get_contract_storage(ch, wrap116_balance_key(from)), from_bal)) {
        return false;
    }
    if (from_bal < amount) {
        return false;
    }
    from_bal -= amount;

    std::uint64_t evt_seq = 0;
    if (!decode_u64_le_(st.get_contract_storage(ch, wrap116_evt_seq_key()), evt_seq)) {
        return false;
    }
    const auto seq = evt_seq + 1;
    if (seq < evt_seq) {
        return false;
    }

    out_storage_changes.emplace_back(wrap_burned_entry_(asset), encode_u64_le_(next_burned));

    out_storage_changes.emplace_back(ch + ":" + crypto::to_hex(wrap116_balance_key(from)), encode_u64_le_(from_bal));
    out_storage_changes.emplace_back(ch + ":" + crypto::to_hex(wrap116_evt_seq_key()), encode_u64_le_(seq));

    std::vector<std::uint8_t> ev;
    ev.reserve(1 + 32 + 32 + 8);
    ev.push_back(0x03);
    ev.insert(ev.end(), from.begin(), from.end());
    ev.insert(ev.end(), crypto::Hash256{}.begin(), crypto::Hash256{}.end());
    const auto ab = encode_u64_le_(amount);
    ev.insert(ev.end(), ab.begin(), ab.end());
    out_storage_changes.emplace_back(ch + ":" + crypto::to_hex(wrap116_evt_key(seq)), ev);

    return true;
}

}

crypto::Hash256 wrap116_balance_key(const crypto::Hash256& addr) {
    return crypto::sha256("wrap116:bal:" + crypto::to_hex(addr));
}

crypto::Hash256 wrap116_evt_seq_key() {
    return crypto::sha256("wrap116:evt_seq");
}

crypto::Hash256 wrap116_evt_key(const std::uint64_t seq) {
    return crypto::sha256("wrap116:evt:" + std::to_string(seq));
}

bool apply_bridge_mint(GlobalState& st,
                      const WrappedAssetId& asset,
                      const crypto::Hash256& to,
                      const std::uint64_t amount,
                      StateDelta& out_delta) {
    if (!asset_ok_(st, asset)) {
        return false;
    }
    StateDelta cd;
    if (!ensure_wrap_contract_(st, asset, cd)) {
        return false;
    }

    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    if (!build_mint_changes_(st, asset, to, amount, storage_changes)) {
        return false;
    }

    return st.apply_batch({}, {}, storage_changes, out_delta);
}

bool apply_bridge_burn(GlobalState& st,
                      const WrappedAssetId& asset,
                      const crypto::Hash256& from,
                      const std::uint64_t amount,
                      StateDelta& out_delta) {
    if (!asset_ok_(st, asset)) {
        return false;
    }
    StateDelta cd;
    if (!ensure_wrap_contract_(st, asset, cd)) {
        return false;
    }

    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    if (!build_burn_changes_(st, asset, from, amount, storage_changes)) {
        return false;
    }

    return st.apply_batch({}, {}, storage_changes, out_delta);
}

bool apply_verified_bridge_op(GlobalState& st,
                             const crypto::Hash256& msg_id,
                             const VerifiedWrapOp& op,
                             StateDelta& out_delta) {
    if (op.action != WrapAction::Mint && op.action != WrapAction::Burn) {
        return false;
    }
    if (!asset_ok_(st, op.asset)) {
        return false;
    }
    if (st.bridge_is_seen(msg_id)) {
        out_delta = StateDelta{};
        return false;
    }

    StateDelta cd;
    if (!ensure_wrap_contract_(st, op.asset, cd)) {
        return false;
    }

    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    storage_changes.emplace_back(bridge_seen_entry_(msg_id), std::vector<std::uint8_t>{1u});

    bool ok = false;
    if (op.action == WrapAction::Mint) {
        ok = build_mint_changes_(st, op.asset, op.account, op.amount, storage_changes);
    } else {
        ok = build_burn_changes_(st, op.asset, op.account, op.amount, storage_changes);
    }
    if (!ok) {
        return false;
    }

    return st.apply_batch({}, {}, storage_changes, out_delta);
}

}
