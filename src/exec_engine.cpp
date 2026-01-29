#include "rand/exec_engine.hpp"

#include "rand/wrap/apply.hpp"
#include "rand/wrap/contract.hpp"

#include "rand/module118/apply.hpp"
#include "rand/module118/contract.hpp"

#include "rand/module119/amm/apply.hpp"
#include "rand/module119/amm/contract.hpp"
#include "rand/module119/lend/apply.hpp"
#include "rand/module119/lend/contract.hpp"

#include "rand/evm_logs.hpp"
#include "rand/vm.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <queue>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace randio {
namespace {

constexpr std::uint8_t kOpTransfer = 0x01;
constexpr std::uint8_t kOpDeploy = 0x02;
constexpr std::uint8_t kOpCall = 0x03;
constexpr std::uint8_t kOpUpgrade = 0x04;

constexpr std::string_view kAcctPrefix = "acct:";
constexpr std::string_view kCodePrefix = "code:";
constexpr std::string_view kStorPrefix = "stor:";

crypto::Hash256 owner_key_hash() {
    return crypto::sha256("owner");
}

std::uint64_t read_u64_le(const std::uint8_t* p);
std::uint32_t read_u32_le(const std::uint8_t* p);

crypto::Hash256 rand20_marker_hash() {
    return crypto::sha256("RAND20");
}

crypto::Hash256 randnft_marker_hash() {
    return crypto::sha256("RANDNFT");
}

std::vector<std::uint8_t> randnft_marker_code() {
    vm::Bytecode bc;
    bc.version = 1;
    bc.code.clear();
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    const auto m = randnft_marker_hash();
    bc.code.insert(bc.code.end(), m.begin(), m.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));
    return vm::VM::encode_bytecode(bc);
}

std::vector<std::uint8_t> rand20_marker_code() {
    vm::Bytecode bc;
    bc.version = 1;
    bc.code.clear();
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    const auto m = rand20_marker_hash();
    bc.code.insert(bc.code.end(), m.begin(), m.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));
    return vm::VM::encode_bytecode(bc);
}

bool is_rand20_contract(const std::vector<std::uint8_t>& code) {
    return code == rand20_marker_code();
}

bool is_randnft_contract(const std::vector<std::uint8_t>& code) {
    return code == randnft_marker_code();
}

std::optional<std::uint64_t> decode_u64(std::span<const std::uint8_t> b) {
    if (b.size() != 8) {
        return std::nullopt;
    }
    return read_u64_le(b.data());
}

std::vector<std::uint8_t> encode_u64(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

crypto::Hash256 rand20_supply_key() {
    return crypto::sha256("rand20:supply");
}

crypto::Hash256 rand20_evt_seq_key() {
    return crypto::sha256("rand20:evt_seq");
}

crypto::Hash256 rand20_balance_key(const crypto::Hash256& addr) {
    const auto hex = crypto::to_hex(addr);
    return crypto::sha256("rand20:bal:" + hex);
}

crypto::Hash256 rand20_evt_key(const std::uint64_t seq) {
    return crypto::sha256("rand20:evt:" + std::to_string(seq));
}

crypto::Hash256 randnft_supply_key() {
    return crypto::sha256("randnft:supply");
}

crypto::Hash256 randnft_evt_seq_key() {
    return crypto::sha256("randnft:evt_seq");
}

crypto::Hash256 randnft_owner_key(const crypto::Hash256& token_id) {
    return crypto::sha256("randnft:owner:" + crypto::to_hex(token_id));
}

crypto::Hash256 randnft_meta_key(const crypto::Hash256& token_id) {
    return crypto::sha256("randnft:meta:" + crypto::to_hex(token_id));
}

crypto::Hash256 randnft_evt_key(const std::uint64_t seq) {
    return crypto::sha256("randnft:evt:" + std::to_string(seq));
}

crypto::Hash256 randnft_token_id(const crypto::Hash256& contract, const std::uint64_t supply_next) {
    const auto c = crypto::to_hex(contract);
    return crypto::sha256("randnft:token:" + c + ":" + std::to_string(supply_next));
}

std::optional<crypto::Hash256> read_addr32(std::span<const std::uint8_t> b) {
    if (b.size() != 32) {
        return std::nullopt;
    }
    crypto::Hash256 out{};
    std::copy(b.begin(), b.end(), out.begin());
    return out;
}

bool read_storage_u64(GlobalState& st, const std::string& contract_hex, const crypto::Hash256& key, std::uint64_t& out) {
    const auto v = st.get_contract_storage(contract_hex, key);
    if (!v) {
        out = 0;
        return true;
    }
    const auto dv = decode_u64(std::span<const std::uint8_t>(v->data(), v->size()));
    if (!dv) {
        return false;
    }
    out = *dv;
    return true;
}

bool read_storage_addr(GlobalState& st, const std::string& contract_hex, const crypto::Hash256& key, crypto::Hash256& out) {
    const auto v = st.get_contract_storage(contract_hex, key);
    if (!v || v->size() != 32) {
        return false;
    }
    std::copy(v->begin(), v->end(), out.begin());
    return true;
}

void set_storage_entry(std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out,
                       const std::string& contract_hex,
                       const crypto::Hash256& key,
                       const std::optional<std::vector<std::uint8_t>>& val) {
    out.emplace_back(contract_hex + ":" + crypto::to_hex(key), val);
}

bool rand20_apply(GlobalState& st,
                 const std::string& caller,
                 const std::string& contract_hex,
                 const std::vector<std::uint8_t>& input,
                 std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
    if (input.size() < 1) {
        return false;
    }

    crypto::Hash256 owner{};
    if (!read_storage_addr(st, contract_hex, owner_key_hash(), owner)) {
        return false;
    }
    const auto caller_addr = crypto::sha256(std::string_view(caller));

    std::uint64_t supply = 0;
    if (!read_storage_u64(st, contract_hex, rand20_supply_key(), supply)) {
        return false;
    }

    std::uint64_t evt_seq = 0;
    if (!read_storage_u64(st, contract_hex, rand20_evt_seq_key(), evt_seq)) {
        return false;
    }

    const auto op = input[0];
    if (op == 0x01 || op == 0x02) {
        if (input.size() != 1 + 32 + 8) {
            return false;
        }
        const auto to = read_addr32(std::span<const std::uint8_t>(input.data() + 1, 32));
        if (!to) {
            return false;
        }
        const auto amt = decode_u64(std::span<const std::uint8_t>(input.data() + 33, 8));
        if (!amt || *amt == 0) {
            return false;
        }

        if (op == 0x02) {
            if (caller_addr != owner) {
                return false;
            }
        }

        auto from_addr = caller_addr;
        if (op == 0x02) {
            from_addr = crypto::Hash256{};
        }

        std::uint64_t from_bal = 0;
        if (op == 0x01) {
            if (!read_storage_u64(st, contract_hex, rand20_balance_key(from_addr), from_bal)) {
                return false;
            }
            if (from_bal < *amt) {
                return false;
            }
            from_bal -= *amt;
            set_storage_entry(out_storage_changes, contract_hex, rand20_balance_key(from_addr), encode_u64(from_bal));
        }

        std::uint64_t to_bal = 0;
        if (!read_storage_u64(st, contract_hex, rand20_balance_key(*to), to_bal)) {
            return false;
        }
        const auto next_to = to_bal + *amt;
        if (next_to < to_bal) {
            return false;
        }
        set_storage_entry(out_storage_changes, contract_hex, rand20_balance_key(*to), encode_u64(next_to));

        if (op == 0x02) {
            const auto next_supply = supply + *amt;
            if (next_supply < supply) {
                return false;
            }
            supply = next_supply;
            set_storage_entry(out_storage_changes, contract_hex, rand20_supply_key(), encode_u64(supply));
        }

        const auto seq = evt_seq + 1;
        if (seq < evt_seq) {
            return false;
        }
        evt_seq = seq;
        set_storage_entry(out_storage_changes, contract_hex, rand20_evt_seq_key(), encode_u64(evt_seq));

        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), from_addr.begin(), from_addr.end());
        ev.insert(ev.end(), to->begin(), to->end());
        const auto ab = encode_u64(*amt);
        ev.insert(ev.end(), ab.begin(), ab.end());
        set_storage_entry(out_storage_changes, contract_hex, rand20_evt_key(evt_seq), ev);
        return true;
    }

    if (op == 0x03) {
        if (input.size() != 1 + 8) {
            return false;
        }
        if (caller_addr != owner) {
            return false;
        }
        const auto amt = decode_u64(std::span<const std::uint8_t>(input.data() + 1, 8));
        if (!amt || *amt == 0) {
            return false;
        }
        std::uint64_t from_bal = 0;
        if (!read_storage_u64(st, contract_hex, rand20_balance_key(caller_addr), from_bal)) {
            return false;
        }
        if (from_bal < *amt) {
            return false;
        }
        from_bal -= *amt;
        set_storage_entry(out_storage_changes, contract_hex, rand20_balance_key(caller_addr), encode_u64(from_bal));
        if (supply < *amt) {
            return false;
        }
        supply -= *amt;
        set_storage_entry(out_storage_changes, contract_hex, rand20_supply_key(), encode_u64(supply));

        const auto seq = evt_seq + 1;
        if (seq < evt_seq) {
            return false;
        }
        evt_seq = seq;
        set_storage_entry(out_storage_changes, contract_hex, rand20_evt_seq_key(), encode_u64(evt_seq));

        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        ev.insert(ev.end(), crypto::Hash256{}.begin(), crypto::Hash256{}.end());
        const auto ab = encode_u64(*amt);
        ev.insert(ev.end(), ab.begin(), ab.end());
        set_storage_entry(out_storage_changes, contract_hex, rand20_evt_key(evt_seq), ev);
        return true;
    }

    return false;
}

bool wrap116_apply(GlobalState& st,
                  const std::string& caller,
                  const std::string& contract_hex,
                  const std::vector<std::uint8_t>& input,
                  std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
    if (input.size() < 1) {
        return false;
    }

    const auto caller_addr = crypto::sha256(std::string_view(caller));

    std::uint64_t evt_seq = 0;
    if (!read_storage_u64(st, contract_hex, module116::wrap116_evt_seq_key(), evt_seq)) {
        return false;
    }

    const auto op = input[0];
    if (op == 0x01) {
        if (input.size() != 1 + 32 + 8) {
            return false;
        }
        const auto to = read_addr32(std::span<const std::uint8_t>(input.data() + 1, 32));
        if (!to) {
            return false;
        }
        const auto amt = decode_u64(std::span<const std::uint8_t>(input.data() + 33, 8));
        if (!amt || *amt == 0) {
            return false;
        }

        std::uint64_t from_bal = 0;
        if (!read_storage_u64(st, contract_hex, module116::wrap116_balance_key(caller_addr), from_bal)) {
            return false;
        }
        if (from_bal < *amt) {
            return false;
        }
        from_bal -= *amt;
        set_storage_entry(out_storage_changes, contract_hex, module116::wrap116_balance_key(caller_addr), encode_u64(from_bal));

        std::uint64_t to_bal = 0;
        if (!read_storage_u64(st, contract_hex, module116::wrap116_balance_key(*to), to_bal)) {
            return false;
        }
        const auto next_to = to_bal + *amt;
        if (next_to < to_bal) {
            return false;
        }
        set_storage_entry(out_storage_changes, contract_hex, module116::wrap116_balance_key(*to), encode_u64(next_to));

        const auto seq = evt_seq + 1;
        if (seq < evt_seq) {
            return false;
        }
        evt_seq = seq;
        set_storage_entry(out_storage_changes, contract_hex, module116::wrap116_evt_seq_key(), encode_u64(evt_seq));

        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 32 + 8);
        ev.push_back(op);
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        ev.insert(ev.end(), to->begin(), to->end());
        const auto ab = encode_u64(*amt);
        ev.insert(ev.end(), ab.begin(), ab.end());
        set_storage_entry(out_storage_changes, contract_hex, module116::wrap116_evt_key(evt_seq), ev);
        return true;
    }

    if (op == 0x02 || op == 0x03) {
        return false;
    }

    return false;
}

bool randnft_apply(GlobalState& st,
                   const std::string& caller,
                   const crypto::Hash256& contract,
                   const std::string& contract_hex,
                   const std::vector<std::uint8_t>& input,
                   std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& out_storage_changes) {
    if (input.empty()) {
        return false;
    }

    crypto::Hash256 owner{};
    if (!read_storage_addr(st, contract_hex, owner_key_hash(), owner)) {
        return false;
    }
    const auto caller_addr = crypto::sha256(std::string_view(caller));

    std::uint64_t supply = 0;
    if (!read_storage_u64(st, contract_hex, randnft_supply_key(), supply)) {
        return false;
    }
    std::uint64_t evt_seq = 0;
    if (!read_storage_u64(st, contract_hex, randnft_evt_seq_key(), evt_seq)) {
        return false;
    }

    const auto op = input[0];

    if (op == 0x01) {
        if (caller_addr != owner) {
            return false;
        }
        if (input.size() < 1 + 32 + 4) {
            return false;
        }
        const auto to = read_addr32(std::span<const std::uint8_t>(input.data() + 1, 32));
        if (!to) {
            return false;
        }
        const auto mlen = read_u32_le(input.data() + 33);
        if (1 + 32 + 4 + static_cast<std::size_t>(mlen) != input.size()) {
            return false;
        }

        const auto next_supply = supply + 1;
        if (next_supply < supply) {
            return false;
        }
        const auto tid = randnft_token_id(contract, next_supply);
        supply = next_supply;
        set_storage_entry(out_storage_changes, contract_hex, randnft_supply_key(), encode_u64(supply));

        std::vector<std::uint8_t> tov(to->begin(), to->end());
        set_storage_entry(out_storage_changes, contract_hex, randnft_owner_key(tid), tov);

        const auto mstart = static_cast<std::size_t>(1 + 32 + 4);
        if (mlen > 0) {
            std::vector<std::uint8_t> meta(input.begin() + static_cast<std::ptrdiff_t>(mstart), input.end());
            set_storage_entry(out_storage_changes, contract_hex, randnft_meta_key(tid), meta);
        }

        const auto seq = evt_seq + 1;
        if (seq < evt_seq) {
            return false;
        }
        evt_seq = seq;
        set_storage_entry(out_storage_changes, contract_hex, randnft_evt_seq_key(), encode_u64(evt_seq));

        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 32 + 32);
        ev.push_back(op);
        ev.insert(ev.end(), tid.begin(), tid.end());
        ev.insert(ev.end(), crypto::Hash256{}.begin(), crypto::Hash256{}.end());
        ev.insert(ev.end(), to->begin(), to->end());
        set_storage_entry(out_storage_changes, contract_hex, randnft_evt_key(evt_seq), ev);
        return true;
    }

    if (op == 0x02) {
        if (input.size() != 1 + 32 + 32) {
            return false;
        }
        crypto::Hash256 tid{};
        std::copy(input.begin() + 1, input.begin() + 33, tid.begin());
        const auto to = read_addr32(std::span<const std::uint8_t>(input.data() + 33, 32));
        if (!to) {
            return false;
        }
        crypto::Hash256 cur_owner{};
        if (!read_storage_addr(st, contract_hex, randnft_owner_key(tid), cur_owner)) {
            return false;
        }
        if (cur_owner != caller_addr) {
            return false;
        }

        std::vector<std::uint8_t> tov(to->begin(), to->end());
        set_storage_entry(out_storage_changes, contract_hex, randnft_owner_key(tid), tov);

        const auto seq = evt_seq + 1;
        if (seq < evt_seq) {
            return false;
        }
        evt_seq = seq;
        set_storage_entry(out_storage_changes, contract_hex, randnft_evt_seq_key(), encode_u64(evt_seq));

        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32 + 32 + 32);
        ev.push_back(op);
        ev.insert(ev.end(), tid.begin(), tid.end());
        ev.insert(ev.end(), caller_addr.begin(), caller_addr.end());
        ev.insert(ev.end(), to->begin(), to->end());
        set_storage_entry(out_storage_changes, contract_hex, randnft_evt_key(evt_seq), ev);
        return true;
    }

    if (op == 0x03) {
        if (caller_addr != owner) {
            return false;
        }
        if (input.size() != 1 + 32) {
            return false;
        }
        crypto::Hash256 tid{};
        std::copy(input.begin() + 1, input.begin() + 33, tid.begin());
        const auto cur = st.get_contract_storage(contract_hex, randnft_owner_key(tid));
        if (!cur || cur->size() != 32) {
            return false;
        }

        set_storage_entry(out_storage_changes, contract_hex, randnft_owner_key(tid), std::nullopt);
        set_storage_entry(out_storage_changes, contract_hex, randnft_meta_key(tid), std::nullopt);

        const auto seq = evt_seq + 1;
        if (seq < evt_seq) {
            return false;
        }
        evt_seq = seq;
        set_storage_entry(out_storage_changes, contract_hex, randnft_evt_seq_key(), encode_u64(evt_seq));

        std::vector<std::uint8_t> ev;
        ev.reserve(1 + 32);
        ev.push_back(op);
        ev.insert(ev.end(), tid.begin(), tid.end());
        set_storage_entry(out_storage_changes, contract_hex, randnft_evt_key(evt_seq), ev);
        return true;
    }

    if (op == 0x04) {
        if (input.size() != 1 + 32) {
            return false;
        }
        crypto::Hash256 tid{};
        std::copy(input.begin() + 1, input.begin() + 33, tid.begin());
        const auto meta = st.get_contract_storage(contract_hex, randnft_meta_key(tid));
        if (!meta) {
            return false;
        }
        return true;
    }

    return false;
}

std::uint64_t read_u64_le(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
    }
    return v;
}

std::uint32_t read_u32_le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
           (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
}

std::string prefixed(std::string_view pfx, std::string_view v) {
    return std::string(pfx) + std::string(v);
}

bool starts_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.substr(0, p.size()) == p;
}

std::string_view strip_prefix(std::string_view s, std::string_view p) {
    if (!starts_with(s, p)) {
        return {};
    }
    return s.substr(p.size());
}

struct Deploy final {
    std::string deployer;
    std::uint64_t gas_limit{0};
    std::vector<std::uint8_t> code;
};

struct Call final {
    std::string caller;
    crypto::Hash256 contract{};
    std::uint64_t gas_limit{0};
    std::vector<std::uint8_t> input;
};

struct Upgrade final {
    std::string caller;
    crypto::Hash256 contract{};
    std::uint64_t gas_limit{0};
    std::vector<std::uint8_t> new_code;
};

std::optional<Deploy> decode_deploy(const Transaction& tx) {
    const auto& p = tx.payload;
    if (p.size() < 1 + 1 + 8 + 4) {
        return std::nullopt;
    }
    if (p[0] != kOpDeploy) {
        return std::nullopt;
    }
    std::size_t off = 1;
    const auto dlen = static_cast<std::size_t>(p[off]);
    off += 1;
    if (off + dlen > p.size()) {
        return std::nullopt;
    }
    std::string deployer(reinterpret_cast<const char*>(p.data() + off), reinterpret_cast<const char*>(p.data() + off + dlen));
    off += dlen;
    if (off + 8 + 4 > p.size()) {
        return std::nullopt;
    }
    const auto gas = read_u64_le(p.data() + off);
    off += 8;
    const auto clen = static_cast<std::size_t>(read_u32_le(p.data() + off));
    off += 4;
    if (off + clen != p.size()) {
        return std::nullopt;
    }
    Deploy d;
    d.deployer = std::move(deployer);
    d.gas_limit = gas;
    d.code.assign(p.begin() + static_cast<std::ptrdiff_t>(off), p.end());
    return d;
}

std::optional<Call> decode_call(const Transaction& tx) {
    const auto& p = tx.payload;
    if (p.size() < 1 + 1 + 32 + 8 + 4) {
        return std::nullopt;
    }
    if (p[0] != kOpCall) {
        return std::nullopt;
    }
    std::size_t off = 1;
    const auto clen = static_cast<std::size_t>(p[off]);
    off += 1;
    if (off + clen > p.size()) {
        return std::nullopt;
    }
    std::string caller(reinterpret_cast<const char*>(p.data() + off), reinterpret_cast<const char*>(p.data() + off + clen));
    off += clen;
    if (off + 32 + 8 + 4 > p.size()) {
        return std::nullopt;
    }
    Call c;
    c.caller = std::move(caller);
    std::copy(p.begin() + static_cast<std::ptrdiff_t>(off), p.begin() + static_cast<std::ptrdiff_t>(off + 32), c.contract.begin());
    off += 32;
    c.gas_limit = read_u64_le(p.data() + off);
    off += 8;
    const auto ilen = static_cast<std::size_t>(read_u32_le(p.data() + off));
    off += 4;
    if (off + ilen != p.size()) {
        return std::nullopt;
    }
    c.input.assign(p.begin() + static_cast<std::ptrdiff_t>(off), p.end());
    return c;
}

std::optional<Upgrade> decode_upgrade(const Transaction& tx) {
    const auto& p = tx.payload;
    if (p.size() < 1 + 1 + 32 + 8 + 4) {
        return std::nullopt;
    }
    if (p[0] != kOpUpgrade) {
        return std::nullopt;
    }
    std::size_t off = 1;
    const auto clen = static_cast<std::size_t>(p[off]);
    off += 1;
    if (off + clen > p.size()) {
        return std::nullopt;
    }
    std::string caller(reinterpret_cast<const char*>(p.data() + off), reinterpret_cast<const char*>(p.data() + off + clen));
    off += clen;
    if (off + 32 + 8 + 4 > p.size()) {
        return std::nullopt;
    }
    Upgrade u;
    u.caller = std::move(caller);
    std::copy(p.begin() + static_cast<std::ptrdiff_t>(off), p.begin() + static_cast<std::ptrdiff_t>(off + 32), u.contract.begin());
    off += 32;
    u.gas_limit = read_u64_le(p.data() + off);
    off += 8;
    const auto nlen = static_cast<std::size_t>(read_u32_le(p.data() + off));
    off += 4;
    if (off + nlen != p.size()) {
        return std::nullopt;
    }
    u.new_code.assign(p.begin() + static_cast<std::ptrdiff_t>(off), p.end());
    return u;
}

[[nodiscard]] std::optional<std::string> sender_for_tx(const Transaction& tx) {
    const auto& p = tx.payload;
    if (p.empty()) {
        return std::nullopt;
    }
    if (p[0] == kOpTransfer) {
        const auto t = DeterministicExecutor::decode_transfer(tx);
        if (!t) {
            return std::nullopt;
        }
        return t->from;
    }
    if (p[0] == kOpDeploy) {
        const auto d = decode_deploy(tx);
        if (!d) {
            return std::nullopt;
        }
        return d->deployer;
    }
    if (p[0] == kOpCall) {
        const auto c = decode_call(tx);
        if (!c) {
            return std::nullopt;
        }
        return c->caller;
    }
    if (p[0] == kOpUpgrade) {
        const auto u = decode_upgrade(tx);
        if (!u) {
            return std::nullopt;
        }
        return u->caller;
    }
    return std::nullopt;
}

[[nodiscard]] std::uint64_t effective_compute_bid_for_tx(const Transaction& tx) {
    if (tx.version < 2) {
        return 0;
    }
    if (tx.compute_limit == 0 && tx.compute_price_per_unit == 0) {
        return 0;
    }

    const auto price = (tx.compute_price_per_unit != 0) ? tx.compute_price_per_unit : tx.priority_fee_per_gas;
    const auto limit = (tx.compute_limit != 0) ? tx.compute_limit : 1;
    if (price == 0 || limit == 0) {
        return 0;
    }
    if (price > (std::numeric_limits<std::uint64_t>::max)() / limit) {
        return (std::numeric_limits<std::uint64_t>::max)();
    }
    return price * limit;
}

struct TxPriorityKey final {
    bool is_v2{false};
    std::uint64_t effective_compute_bid{0};
    std::uint64_t priority_fee_per_gas{0};
    std::uint64_t fee_rate_per_byte{0};
    std::uint64_t fee{0};
    crypto::Hash256 id{};
};

[[nodiscard]] TxPriorityKey priority_key_for_tx(const Transaction& tx) {
    TxPriorityKey k;
    k.is_v2 = tx.version >= 2;
    k.effective_compute_bid = effective_compute_bid_for_tx(tx);
    k.priority_fee_per_gas = tx.priority_fee_per_gas;
    const auto bytes = serialize_tx(tx).size();
    const auto b = static_cast<std::uint64_t>(bytes);
    k.fee_rate_per_byte = (b == 0) ? 0 : (tx.fee + b - 1) / b;
    k.fee = tx.fee;
    k.id = txid(tx);
    return k;
}

struct TxPriorityLess final {
    bool operator()(const TxPriorityKey& a, const TxPriorityKey& b) const {
        if (a.is_v2 != b.is_v2) {
            return a.is_v2;
        }
        if (a.is_v2) {
            if (a.effective_compute_bid != b.effective_compute_bid) {
                return a.effective_compute_bid > b.effective_compute_bid;
            }
            if (a.priority_fee_per_gas != b.priority_fee_per_gas) {
                return a.priority_fee_per_gas > b.priority_fee_per_gas;
            }
            return a.id < b.id;
        }
        if (a.fee_rate_per_byte != b.fee_rate_per_byte) {
            return a.fee_rate_per_byte > b.fee_rate_per_byte;
        }
        if (a.fee != b.fee) {
            return a.fee > b.fee;
        }
        return a.id < b.id;
    }
};

}

TransactionScheduler::TransactionScheduler(Options opt) : opt_(opt) {}

Batch TransactionScheduler::build_batch(const Mempool& mempool) const {
    Batch b;
    b.rejected.clear();

    struct AccountQueueItem final {
        ScheduledTx st;
        std::size_t bytes{0};
        TxPriorityKey key;
    };

    std::map<std::string, std::vector<AccountQueueItem>> by_sender;

    const auto ordered_all = mempool.ordered_txs(mempool.size());
    for (const auto& tx : ordered_all) {
        const auto rw = DeterministicExecutor::rwset_for_tx(tx);
        if (!rw) {
            ScheduledTx st;
            st.tx = tx;
            st.id = txid(tx);
            st.compute = DeterministicExecutor::compute_for_tx(tx);
            b.rejected.push_back(std::move(st));
            continue;
        }

        const auto sender = sender_for_tx(tx);
        if (!sender) {
            ScheduledTx st;
            st.tx = tx;
            st.id = txid(tx);
            st.compute = DeterministicExecutor::compute_for_tx(tx);
            b.rejected.push_back(std::move(st));
            continue;
        }

        AccountQueueItem it;
        it.bytes = serialize_tx(tx).size();
        it.key = priority_key_for_tx(tx);
        it.st.tx = tx;
        it.st.id = it.key.id;
        it.st.compute = DeterministicExecutor::compute_for_tx(tx);
        it.st.rw = *rw;
        by_sender[*sender].push_back(std::move(it));
    }

    for (auto& kv : by_sender) {
        auto& q = kv.second;
        std::sort(q.begin(), q.end(), [](const AccountQueueItem& a, const AccountQueueItem& b) {
            if (a.st.tx.nonce != b.st.tx.nonce) {
                return a.st.tx.nonce < b.st.tx.nonce;
            }
            if (TxPriorityLess{}(a.key, b.key)) {
                return true;
            }
            if (TxPriorityLess{}(b.key, a.key)) {
                return false;
            }
            return a.key.id < b.key.id;
        });
    }

    struct Cursor final {
        std::string sender;
        std::size_t idx{0};
        TxPriorityKey key;
    };

    struct CursorBestFirst final {
        bool operator()(const Cursor& a, const Cursor& b) const {
            if (TxPriorityLess{}(a.key, b.key)) {
                return true;
            }
            if (TxPriorityLess{}(b.key, a.key)) {
                return false;
            }
            return a.sender < b.sender;
        }
    };

    std::size_t total_bytes = 0;
    std::unordered_map<std::string, std::uint64_t> used_compute;
    used_compute.reserve(by_sender.size());

    std::set<Cursor, CursorBestFirst> cursors;
    for (const auto& kv : by_sender) {
        if (!kv.second.empty()) {
            Cursor c;
            c.sender = kv.first;
            c.idx = 0;
            c.key = kv.second[0].key;
            cursors.insert(std::move(c));
        }
    }

    while (!cursors.empty() && b.txs.size() < opt_.max_batch_txs) {
        auto itc = cursors.begin();
        Cursor c = *itc;
        cursors.erase(itc);

        auto& q = by_sender.at(c.sender);
        if (c.idx >= q.size()) {
            continue;
        }
        const auto& item = q[c.idx];

        const auto u = used_compute.find(c.sender);
        const std::uint64_t cur = (u == used_compute.end()) ? 0 : u->second;
        if (cur > opt_.max_account_compute_per_batch || item.st.compute > opt_.max_account_compute_per_batch - cur) {
            continue;
        }

        if (total_bytes + item.bytes > opt_.max_batch_bytes) {
            b.rejected.push_back(item.st);
        } else {
            b.txs.push_back(item.st);
            total_bytes += item.bytes;
            used_compute[c.sender] = cur + item.st.compute;
        }

        c.idx += 1;
        if (c.idx < q.size()) {
            c.key = q[c.idx].key;
            cursors.insert(std::move(c));
        }
    }

    return b;
}

bool ExecutionPlanner::conflicts(const ReadWriteSet& a, const ReadWriteSet& b) {
    auto intersects = [](const std::vector<std::string>& x, const std::vector<std::string>& y) {
        for (const auto& s : x) {
            if (std::find(y.begin(), y.end(), s) != y.end()) {
                return true;
            }
        }
        return false;
    };

    if (intersects(a.writes, b.writes)) {
        return true;
    }
    if (intersects(a.writes, b.reads)) {
        return true;
    }
    if (intersects(a.reads, b.writes)) {
        return true;
    }
    return false;
}

ExecutionPlan ExecutionPlanner::plan(const Batch& b) {
    ExecutionPlan p;

    p.rejected = b.rejected;
    std::sort(p.rejected.begin(), p.rejected.end(), [](const ScheduledTx& a, const ScheduledTx& b) { return a.id < b.id; });
    p.rejected.erase(std::unique(p.rejected.begin(), p.rejected.end(), [](const ScheduledTx& a, const ScheduledTx& b) { return a.id == b.id; }),
                     p.rejected.end());

    for (const auto& tx : b.txs) {
        bool placed = false;
        for (auto& g : p.groups) {
            bool ok = true;
            for (const auto& other : g.txs) {
                if (conflicts(tx.rw, other.rw)) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                g.txs.push_back(tx);
                placed = true;
                break;
            }
        }
        if (!placed) {
            ExecutionGroup g;
            g.txs.push_back(tx);
            p.groups.push_back(std::move(g));
        }
    }

    return p;
}

DeterministicExecutor::DeterministicExecutor(Options opt) : opt_(opt) {}

bool DeterministicExecutor::same_account_opt(const std::optional<Account>& a, const std::optional<Account>& b) {
    if (a.has_value() != b.has_value()) {
        return false;
    }
    if (!a) {
        return true;
    }
    return a->nonce == b->nonce && a->balance == b->balance;
}

std::uint64_t DeterministicExecutor::compute_for_tx(const Transaction& tx) {
    return 1 + static_cast<std::uint64_t>(tx.payload.size());
}

std::optional<ReadWriteSet> DeterministicExecutor::rwset_for_tx(const Transaction& tx) {
    const auto& p = tx.payload;
    if (p.empty()) {
        return std::nullopt;
    }

    ReadWriteSet rw;

    if (p[0] == kOpTransfer) {
        const auto t = decode_transfer(tx);
        if (!t) {
            return std::nullopt;
        }
        rw.reads = {prefixed(kAcctPrefix, t->from), prefixed(kAcctPrefix, t->to)};
        rw.writes = {prefixed(kAcctPrefix, t->from), prefixed(kAcctPrefix, t->to)};
    } else if (p[0] == kOpDeploy) {
        const auto d = decode_deploy(tx);
        if (!d) {
            return std::nullopt;
        }
        const auto id = txid(tx);
        const auto contract = crypto::sha256(std::span<const std::uint8_t>(id.data(), id.size()));
        const auto ch = crypto::to_hex(contract);
        const auto deployer = prefixed(kAcctPrefix, d->deployer);
        rw.reads = {deployer};
        rw.writes = {deployer, prefixed(kCodePrefix, ch), prefixed(kStorPrefix, ch)};
    } else if (p[0] == kOpCall) {
        const auto c = decode_call(tx);
        if (!c) {
            return std::nullopt;
        }
        const auto caller = prefixed(kAcctPrefix, c->caller);
        const auto ch = crypto::to_hex(c->contract);
        rw.reads = {caller, prefixed(kCodePrefix, ch), prefixed(kStorPrefix, ch)};
        rw.writes = {caller, prefixed(kStorPrefix, ch)};
    } else if (p[0] == kOpUpgrade) {
        const auto u = decode_upgrade(tx);
        if (!u) {
            return std::nullopt;
        }
        const auto caller = prefixed(kAcctPrefix, u->caller);
        const auto ch = crypto::to_hex(u->contract);
        rw.reads = {caller, prefixed(kCodePrefix, ch), prefixed(kStorPrefix, ch)};
        rw.writes = {caller, prefixed(kCodePrefix, ch), prefixed(kStorPrefix, ch)};
    } else {
        return std::nullopt;
    }

    std::sort(rw.reads.begin(), rw.reads.end());
    rw.reads.erase(std::unique(rw.reads.begin(), rw.reads.end()), rw.reads.end());
    std::sort(rw.writes.begin(), rw.writes.end());
    rw.writes.erase(std::unique(rw.writes.begin(), rw.writes.end()), rw.writes.end());
    return rw;
}

std::optional<Transfer> DeterministicExecutor::decode_transfer(const Transaction& tx) {
    const auto& p = tx.payload;
    if (p.size() < 1 + 1 + 1 + 8 + 8) {
        return std::nullopt;
    }
    if (p[0] != kOpTransfer) {
        return std::nullopt;
    }

    std::size_t off = 1;
    const auto from_len = static_cast<std::size_t>(p[off]);
    off += 1;
    if (off + from_len > p.size()) {
        return std::nullopt;
    }
    std::string from(reinterpret_cast<const char*>(p.data() + off), reinterpret_cast<const char*>(p.data() + off + from_len));
    off += from_len;

    if (off >= p.size()) {
        return std::nullopt;
    }
    const auto to_len = static_cast<std::size_t>(p[off]);
    off += 1;
    if (off + to_len > p.size()) {
        return std::nullopt;
    }
    std::string to(reinterpret_cast<const char*>(p.data() + off), reinterpret_cast<const char*>(p.data() + off + to_len));
    off += to_len;

    if (off + 16 != p.size()) {
        return std::nullopt;
    }

    const auto amount = read_u64_le(p.data() + off);
    const auto expected_nonce = read_u64_le(p.data() + off + 8);

    Transfer t;
    t.from = std::move(from);
    t.to = std::move(to);
    t.amount = amount;
    t.fee = tx.fee;
    t.expected_nonce = expected_nonce;
    return t;
}

ExecutionResult DeterministicExecutor::execute(GlobalState& state, const ExecutionPlan& plan, const std::uint64_t current_height) const {
    ExecutionResult r;

    (void)current_height;

    r.rejected.clear();
    for (const auto& tx : plan.rejected) {
        r.rejected.push_back(tx.id);
    }
    std::sort(r.rejected.begin(), r.rejected.end());
    r.rejected.erase(std::unique(r.rejected.begin(), r.rejected.end()), r.rejected.end());

    if (state.halted()) {
        r.applied.clear();
        r.aborted.clear();
        for (const auto& g : plan.groups) {
            for (const auto& tx : g.txs) {
                r.aborted.push_back(tx.id);
            }
        }
        std::sort(r.aborted.begin(), r.aborted.end());
        r.aborted.erase(std::unique(r.aborted.begin(), r.aborted.end()), r.aborted.end());
        r.state_root = state.state_root();

        r.tx_results.clear();
        std::vector<crypto::Hash256> all = r.aborted;
        all.insert(all.end(), r.rejected.begin(), r.rejected.end());
        std::sort(all.begin(), all.end());
        all.erase(std::unique(all.begin(), all.end()), all.end());
        r.tx_results.reserve(all.size());
        for (const auto& id : all) {
            ExecutionResult::TxResult tr;
            tr.id = id;
            if (std::find(r.rejected.begin(), r.rejected.end(), id) != r.rejected.end()) {
                tr.status = ExecutionResult::TxStatus::Rejected;
                tr.reason = ExecutionResult::ReasonCode::Rejected;
            } else {
                tr.status = ExecutionResult::TxStatus::Aborted;
                tr.reason = ExecutionResult::ReasonCode::Aborted;
            }
            tr.fee_charged = 0;
            tr.gas_used = 0;
            r.tx_results.push_back(tr);
        }
        r.delta = ExecutionResult::DeltaSummary{};
        return r;
    }

    const auto base_fee_per_gas = state.base_fee_per_gas();

    auto max_fee_per_gas = [](const Transaction& tx) {
        return (tx.max_fee_per_gas != 0) ? tx.max_fee_per_gas : tx.fee;
    };

    auto compute_fee_split = [&](const Transaction& tx,
                                 const std::uint64_t gas_used,
                                 std::uint64_t& out_total,
                                 std::uint64_t& out_burn,
                                 std::uint64_t& out_tip) -> bool {
        out_total = 0;
        out_burn = 0;
        out_tip = 0;

        if (tx.version < 2) {
            out_total = tx.fee;
            out_burn = tx.fee;
            out_tip = 0;
            return true;
        }

        const auto max_fee = max_fee_per_gas(tx);
        if (max_fee < base_fee_per_gas) {
            return false;
        }

        const unsigned __int128 burn128 = static_cast<unsigned __int128>(base_fee_per_gas) * static_cast<unsigned __int128>(gas_used);
        if (burn128 > (std::numeric_limits<std::uint64_t>::max)()) {
            return false;
        }
        out_burn = static_cast<std::uint64_t>(burn128);

        const auto room = max_fee - base_fee_per_gas;
        const auto tip_per_gas = (tx.priority_fee_per_gas < room) ? tx.priority_fee_per_gas : room;
        const unsigned __int128 tip128 = static_cast<unsigned __int128>(tip_per_gas) * static_cast<unsigned __int128>(gas_used);
        if (tip128 > (std::numeric_limits<std::uint64_t>::max)()) {
            return false;
        }
        out_tip = static_cast<std::uint64_t>(tip128);

        const auto total = out_burn + out_tip;
        if (total < out_burn) {
            return false;
        }
        out_total = total;
        return true;
    };

    std::vector<crypto::Hash256> applied_all;
    std::vector<crypto::Hash256> aborted_all;
    std::uint64_t burned_fees = 0;
    std::uint64_t total_tips = 0;
    std::uint64_t total_gas_used = 0;
    std::vector<std::pair<crypto::Hash256, StateDelta>> applied_deltas;
    std::unordered_set<std::string> retryable_ids;
    std::unordered_map<std::string, std::pair<std::uint64_t, std::uint64_t>> fee_gas_by_id;

    for (const auto& g0 : plan.groups) {
        std::vector<ScheduledTx> remaining = g0.txs;
        std::sort(remaining.begin(), remaining.end(), [](const ScheduledTx& a, const ScheduledTx& b) { return a.id < b.id; });

        for (int pass = 0; pass < 3 && !remaining.empty(); ++pass) {
            std::vector<std::string> acct_reads;
            std::vector<std::string> code_reads;
            for (const auto& st : remaining) {
                for (const auto& k : st.rw.reads) {
                    if (starts_with(k, kAcctPrefix)) {
                        acct_reads.push_back(std::string(strip_prefix(k, kAcctPrefix)));
                    } else if (starts_with(k, kCodePrefix)) {
                        code_reads.push_back(std::string(strip_prefix(k, kCodePrefix)));
                    }
                }
            }
            std::sort(acct_reads.begin(), acct_reads.end());
            acct_reads.erase(std::unique(acct_reads.begin(), acct_reads.end()), acct_reads.end());
            std::sort(code_reads.begin(), code_reads.end());
            code_reads.erase(std::unique(code_reads.begin(), code_reads.end()), code_reads.end());

            std::unordered_map<std::string, std::optional<Account>> snap_acct;
            snap_acct.reserve(acct_reads.size());
            for (const auto& id : acct_reads) {
                snap_acct[id] = state.get_account(id);
            }

            std::unordered_map<std::string, crypto::Hash256> snap_code_hash;
            snap_code_hash.reserve(code_reads.size());
            for (const auto& ch : code_reads) {
                const auto code = state.get_contract_code(ch);
                const auto h = code ? crypto::sha256(std::span<const std::uint8_t>(code->data(), code->size())) : crypto::sha256(std::string_view{});
                snap_code_hash[ch] = h;
            }

            std::vector<TxEffect> effects;
            effects.reserve(remaining.size());

            for (const auto& stx : remaining) {
                TxEffect e;
                e.id = stx.id;
                e.ok = false;
                e.retryable = false;
                e.fee = stx.tx.fee;
                e.fee_burn = 0;
                e.fee_tip = 0;
                e.gas_used = compute_for_tx(stx.tx);

                e.read_ids = stx.rw.reads;
                std::sort(e.read_ids.begin(), e.read_ids.end());
                e.read_ids.erase(std::unique(e.read_ids.begin(), e.read_ids.end()), e.read_ids.end());

                const auto& p = stx.tx.payload;
                if (p.empty()) {
                    effects.push_back(std::move(e));
                    continue;
                }

                if (stx.tx.version > state.protocol_version()) {
                    effects.push_back(std::move(e));
                    continue;
                }

                if (p[0] == kOpTransfer) {
                    const auto t = decode_transfer(stx.tx);
                    if (!t) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    const auto from_snap = snap_acct[t->from];
                    const auto to_snap = snap_acct[t->to];
                    if (!from_snap) {
                        e.retryable = true;
                        retryable_ids.insert(crypto::to_hex(e.id));
                        effects.push_back(std::move(e));
                        continue;
                    }
                    if (from_snap->nonce != t->expected_nonce) {
                        e.retryable = true;
                        retryable_ids.insert(crypto::to_hex(e.id));
                        effects.push_back(std::move(e));
                        continue;
                    }
                    std::uint64_t fee_total = 0;
                    std::uint64_t fee_burn = 0;
                    std::uint64_t fee_tip = 0;
                    if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    const std::uint64_t total = t->amount + fee_total;
                    if (total < t->amount) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    if (from_snap->balance < total) {
                        e.retryable = true;
                        retryable_ids.insert(crypto::to_hex(e.id));
                        effects.push_back(std::move(e));
                        continue;
                    }
                    Account from_next = *from_snap;
                    from_next.balance -= total;
                    from_next.nonce += 1;
                    Account to_next = to_snap.value_or(Account{});
                    const auto new_to_bal = to_next.balance + t->amount;
                    if (new_to_bal < to_next.balance) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    to_next.balance = new_to_bal;
                    e.fee = fee_total;
                    e.fee_burn = fee_burn;
                    e.fee_tip = fee_tip;
                    e.changes.push_back(AccountChange{t->from, from_next});
                    e.changes.push_back(AccountChange{t->to, to_next});
                    e.ok = true;
                    effects.push_back(std::move(e));
                    continue;
                }

                if (p[0] == kOpDeploy) {
                    const auto d = decode_deploy(stx.tx);
                    if (!d) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    const auto deployer_acc = snap_acct[d->deployer];
                    if (!deployer_acc) {
                        e.retryable = true;
                        retryable_ids.insert(crypto::to_hex(e.id));
                        effects.push_back(std::move(e));
                        continue;
                    }
                    if (deployer_acc->nonce != stx.tx.nonce) {
                        e.retryable = true;
                        retryable_ids.insert(crypto::to_hex(e.id));
                        effects.push_back(std::move(e));
                        continue;
                    }

                    const auto bc = vm::VM::decode_bytecode(std::span<const std::uint8_t>(d->code.data(), d->code.size()));
                    if (!bc) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    vm::VM vm(vm::VM::Options{});
                    if (!vm.validate(*bc)) {
                        effects.push_back(std::move(e));
                        continue;
                    }

                    const auto contract = crypto::sha256(std::span<const std::uint8_t>(stx.id.data(), stx.id.size()));
                    const auto contract_hex = crypto::to_hex(contract);

                    std::uint64_t fee_total = 0;
                    std::uint64_t fee_burn = 0;
                    std::uint64_t fee_tip = 0;
                    if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    if (deployer_acc->balance < fee_total) {
                        e.retryable = true;
                        retryable_ids.insert(crypto::to_hex(e.id));
                        effects.push_back(std::move(e));
                        continue;
                    }

                    Account next = *deployer_acc;
                    next.balance -= fee_total;
                    next.nonce += 1;
                    e.fee = fee_total;
                    e.fee_burn = fee_burn;
                    e.fee_tip = fee_tip;
                    e.changes.push_back(AccountChange{d->deployer, next});

                    e.code_changes.emplace_back(contract_hex, d->code);

                    const auto owner_key = owner_key_hash();
                    const auto owner_entry = contract_hex + ":" + crypto::to_hex(owner_key);
                    const auto caller_addr = crypto::sha256(std::string_view(d->deployer));
                    std::vector<std::uint8_t> owner_val(caller_addr.begin(), caller_addr.end());
                    e.storage_changes.emplace_back(owner_entry, std::move(owner_val));

                    e.ok = true;
                    effects.push_back(std::move(e));
                    continue;
                }

                if (p[0] == kOpCall) {
                    const auto c = decode_call(stx.tx);
                    if (!c) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    const auto caller_acc = snap_acct[c->caller];
                    if (!caller_acc) {
                        e.retryable = true;
                        retryable_ids.insert(crypto::to_hex(e.id));
                        effects.push_back(std::move(e));
                        continue;
                    }
                    if (caller_acc->nonce != stx.tx.nonce) {
                        e.retryable = true;
                        retryable_ids.insert(crypto::to_hex(e.id));
                        effects.push_back(std::move(e));
                        continue;
                    }

                    const auto contract_hex = crypto::to_hex(c->contract);
                    const auto code_bytes = state.get_contract_code(contract_hex);
                    if (!code_bytes) {
                        effects.push_back(std::move(e));
                        continue;
                    }

                    if (is_rand20_contract(*code_bytes)) {
                        if (!rand20_apply(state, c->caller, contract_hex, c->input, e.storage_changes)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        std::uint64_t fee_total = 0;
                        std::uint64_t fee_burn = 0;
                        std::uint64_t fee_tip = 0;
                        if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        if (caller_acc->balance < fee_total) {
                            e.retryable = true;
                            retryable_ids.insert(crypto::to_hex(e.id));
                            effects.push_back(std::move(e));
                            continue;
                        }
                        {
                            Account next = *caller_acc;
                            next.balance -= fee_total;
                            next.nonce += 1;
                            e.changes.push_back(AccountChange{c->caller, next});
                        }
                        e.fee = fee_total;
                        e.fee_burn = fee_burn;
                        e.fee_tip = fee_tip;
                        e.ok = true;
                        effects.push_back(std::move(e));
                        continue;
                    }

                    if (is_randnft_contract(*code_bytes)) {
                        if (!randnft_apply(state, c->caller, c->contract, contract_hex, c->input, e.storage_changes)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        std::uint64_t fee_total = 0;
                        std::uint64_t fee_burn = 0;
                        std::uint64_t fee_tip = 0;
                        if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        if (caller_acc->balance < fee_total) {
                            e.retryable = true;
                            retryable_ids.insert(crypto::to_hex(e.id));
                            effects.push_back(std::move(e));
                            continue;
                        }
                        {
                            Account next = *caller_acc;
                            next.balance -= fee_total;
                            next.nonce += 1;
                            e.changes.push_back(AccountChange{c->caller, next});
                        }
                        e.fee = fee_total;
                        e.fee_burn = fee_burn;
                        e.fee_tip = fee_tip;
                        e.ok = true;
                        effects.push_back(std::move(e));
                        continue;
                    }

                    if (module116::is_wrap116_contract(*code_bytes)) {
                        if (!wrap116_apply(state, c->caller, contract_hex, c->input, e.storage_changes)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        std::uint64_t fee_total = 0;
                        std::uint64_t fee_burn = 0;
                        std::uint64_t fee_tip = 0;
                        if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        if (caller_acc->balance < fee_total) {
                            e.retryable = true;
                            retryable_ids.insert(crypto::to_hex(e.id));
                            effects.push_back(std::move(e));
                            continue;
                        }
                        {
                            Account next = *caller_acc;
                            next.balance -= fee_total;
                            next.nonce += 1;
                            e.changes.push_back(AccountChange{c->caller, next});
                        }
                        e.fee = fee_total;
                        e.fee_burn = fee_burn;
                        e.fee_tip = fee_tip;
                        e.ok = true;
                        effects.push_back(std::move(e));
                        continue;
                    }

                    if (module118::is_stable118_contract(*code_bytes)) {
                        std::vector<std::pair<std::string, std::optional<Account>>> stable_acct_changes;
                        if (!module118::stable118_apply(state, c->caller, contract_hex, c->input, current_height, stable_acct_changes, e.storage_changes)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        for (const auto& [id, next] : stable_acct_changes) {
                            e.changes.push_back(AccountChange{id, next});
                        }
                        std::uint64_t fee_total = 0;
                        std::uint64_t fee_burn = 0;
                        std::uint64_t fee_tip = 0;
                        if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                            effects.push_back(std::move(e));
                            continue;
                        }

                        std::optional<Account> caller_after_stable;
                        for (const auto& [id, next] : stable_acct_changes) {
                            if (id == c->caller) {
                                caller_after_stable = next;
                                break;
                            }
                        }
                        if (!caller_after_stable.has_value()) {
                            caller_after_stable = *caller_acc;
                        }
                        if (caller_after_stable->balance < fee_total) {
                            e.retryable = true;
                            retryable_ids.insert(crypto::to_hex(e.id));
                            effects.push_back(std::move(e));
                            continue;
                        }
                        caller_after_stable->balance -= fee_total;
                        caller_after_stable->nonce += 1;
                        {
                            bool replaced = false;
                            for (auto& ch : e.changes) {
                                if (ch.id == c->caller) {
                                    ch.next = *caller_after_stable;
                                    replaced = true;
                                    break;
                                }
                            }
                            if (!replaced) {
                                e.changes.push_back(AccountChange{c->caller, *caller_after_stable});
                            }
                        }
                        e.fee = fee_total;
                        e.fee_burn = fee_burn;
                        e.fee_tip = fee_tip;
                        e.ok = true;
                        effects.push_back(std::move(e));
                        continue;
                    }

                    if (module119::amm::is_amm119_contract(*code_bytes)) {
                        if (!module119::amm::amm119_apply(state, c->caller, contract_hex, c->input, stx.id, e.storage_changes)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        std::uint64_t fee_total = 0;
                        std::uint64_t fee_burn = 0;
                        std::uint64_t fee_tip = 0;
                        if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        if (caller_acc->balance < fee_total) {
                            e.retryable = true;
                            retryable_ids.insert(crypto::to_hex(e.id));
                            effects.push_back(std::move(e));
                            continue;
                        }
                        {
                            Account next = *caller_acc;
                            next.balance -= fee_total;
                            next.nonce += 1;
                            e.changes.push_back(AccountChange{c->caller, next});
                        }
                        e.fee = fee_total;
                        e.fee_burn = fee_burn;
                        e.fee_tip = fee_tip;
                        e.ok = true;
                        effects.push_back(std::move(e));
                        continue;
                    }

                    if (module119::lend::is_lend119_contract(*code_bytes)) {
                        std::vector<std::pair<std::string, std::optional<Account>>> lend_acct_changes;
                        if (!module119::lend::lend119_apply(state, c->caller, contract_hex, c->input, stx.id, current_height, lend_acct_changes, e.storage_changes)) {
                            effects.push_back(std::move(e));
                            continue;
                        }
                        for (const auto& [id, next] : lend_acct_changes) {
                            e.changes.push_back(AccountChange{id, next});
                        }
                        std::uint64_t fee_total = 0;
                        std::uint64_t fee_burn = 0;
                        std::uint64_t fee_tip = 0;
                        if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                            effects.push_back(std::move(e));
                            continue;
                        }

                        std::optional<Account> caller_after_lend;
                        for (const auto& [id, next] : lend_acct_changes) {
                            if (id == c->caller) {
                                caller_after_lend = next;
                                break;
                            }
                        }
                        if (!caller_after_lend.has_value()) {
                            caller_after_lend = *caller_acc;
                        }
                        if (caller_after_lend->balance < fee_total) {
                            e.retryable = true;
                            retryable_ids.insert(crypto::to_hex(e.id));
                            effects.push_back(std::move(e));
                            continue;
                        }
                        caller_after_lend->balance -= fee_total;
                        caller_after_lend->nonce += 1;
                        {
                            bool replaced = false;
                            for (auto& ch : e.changes) {
                                if (ch.id == c->caller) {
                                    ch.next = *caller_after_lend;
                                    replaced = true;
                                    break;
                                }
                            }
                            if (!replaced) {
                                e.changes.push_back(AccountChange{c->caller, *caller_after_lend});
                            }
                        }
                        e.fee = fee_total;
                        e.fee_burn = fee_burn;
                        e.fee_tip = fee_tip;
                        e.ok = true;
                        effects.push_back(std::move(e));
                        continue;
                    }

                    const auto bc = vm::VM::decode_bytecode(std::span<const std::uint8_t>(code_bytes->data(), code_bytes->size()));
                    if (!bc) {
                        effects.push_back(std::move(e));
                        continue;
                    }

                    vm::VM vm(vm::VM::Options{});
                    if (!vm.validate(*bc)) {
                        effects.push_back(std::move(e));
                        continue;
                    }

                    vm::Host host;
                    host.storage_get = [&](vm::Address addr, crypto::Hash256 key) -> std::optional<std::vector<std::uint8_t>> {
                        const auto hex = crypto::to_hex(addr);
                        const auto v = state.get_contract_storage(hex, key);
                        if (!v) {
                            return std::nullopt;
                        }
                        return *v;
                    };
                    host.storage_set = [&](std::vector<vm::StorageWrite>& out, vm::Address addr, crypto::Hash256 key, std::vector<std::uint8_t> value) {
                        vm::StorageWrite w;
                        w.contract = addr;
                        w.key = key;
                        w.value = std::move(value);
                        out.push_back(std::move(w));
                    };
                    host.get_code = [&](vm::Address addr) -> std::optional<std::vector<std::uint8_t>> {
                        const auto hex = crypto::to_hex(addr);
                        const auto v = state.get_contract_code(hex);
                        if (!v) {
                            return std::nullopt;
                        }
                        return *v;
                    };

                    vm::ExecutionContext ctx;
                    ctx.caller = crypto::sha256(std::string_view(c->caller));
                    ctx.self = c->contract;
                    ctx.value = 0;
                    ctx.gas_limit = c->gas_limit;
                    ctx.depth = 0;

                    const auto vmr = vm.execute(*bc, ctx, host, std::span<const std::uint8_t>(c->input.data(), c->input.size()));
                    if (vmr.status != vm::Status::Ok) {
                        effects.push_back(std::move(e));
                        continue;
                    }

                    e.gas_used = vmr.gas_used;

                    std::uint64_t fee_total = 0;
                    std::uint64_t fee_burn = 0;
                    std::uint64_t fee_tip = 0;
                    if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    if (caller_acc->balance < fee_total) {
                        e.retryable = true;
                        retryable_ids.insert(crypto::to_hex(e.id));
                        effects.push_back(std::move(e));
                        continue;
                    }
                    {
                        Account next = *caller_acc;
                        next.balance -= fee_total;
                        next.nonce += 1;
                        e.changes.push_back(AccountChange{c->caller, next});
                    }
                    e.fee = fee_total;
                    e.fee_burn = fee_burn;
                    e.fee_tip = fee_tip;

                    for (const auto& w : vmr.writes) {
                        const auto ch = crypto::to_hex(w.contract);
                        const auto entry = ch + ":" + crypto::to_hex(w.key);
                        if (w.value.empty()) {
                            e.storage_changes.emplace_back(entry, std::nullopt);
                        } else {
                            e.storage_changes.emplace_back(entry, w.value);
                        }
                    }

                    {
                        module106::EncodeOptions lopt;
                        lopt.max_topics = 4;
                        lopt.max_data_bytes = 256 * 1024;

                        if (vmr.events.size() > 256) {
                            effects.push_back(std::move(e));
                            continue;
                        }

                        const auto count_entry = module106::log_count_key(stx.id);
                        e.storage_changes.emplace_back(count_entry, module106::encode_u64_le(static_cast<std::uint64_t>(vmr.events.size())));

                        for (std::size_t i = 0; i < vmr.events.size(); ++i) {
                            const auto& ev = vmr.events[i];
                            module106::LogRecord rec;
                            rec.address = ev.contract;
                            rec.topics.clear();
                            rec.topics.push_back(ev.topic);
                            rec.data = ev.data;

                            const auto enc = module106::encode_log_record(rec, lopt);
                            if (enc.empty()) {
                                effects.push_back(std::move(e));
                                goto next_effect;
                            }
                            e.storage_changes.emplace_back(module106::log_entry_key(stx.id, static_cast<std::uint32_t>(i)), enc);
                        }
                    }

                    e.ok = true;
                    effects.push_back(std::move(e));
                    next_effect:
                    continue;
                }

                if (p[0] == kOpUpgrade) {
                    const auto u = decode_upgrade(stx.tx);
                    if (!u) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    const auto caller_acc = snap_acct[u->caller];
                    if (!caller_acc) {
                        e.retryable = true;
                        effects.push_back(std::move(e));
                        continue;
                    }
                    if (caller_acc->nonce != stx.tx.nonce) {
                        e.retryable = true;
                        effects.push_back(std::move(e));
                        continue;
                    }

                    const auto contract_hex = crypto::to_hex(u->contract);
                    const auto owner_key = owner_key_hash();
                    const auto owner = state.get_contract_storage(contract_hex, owner_key);
                    if (!owner || owner->size() != 32) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    const auto caller_addr = crypto::sha256(std::string_view(u->caller));
                    if (!std::equal(caller_addr.begin(), caller_addr.end(), owner->begin())) {
                        effects.push_back(std::move(e));
                        continue;
                    }

                    const auto bc = vm::VM::decode_bytecode(std::span<const std::uint8_t>(u->new_code.data(), u->new_code.size()));
                    if (!bc) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    vm::VM vm(vm::VM::Options{});
                    if (!vm.validate(*bc)) {
                        effects.push_back(std::move(e));
                        continue;
                    }

                    std::uint64_t fee_total = 0;
                    std::uint64_t fee_burn = 0;
                    std::uint64_t fee_tip = 0;
                    if (!compute_fee_split(stx.tx, e.gas_used, fee_total, fee_burn, fee_tip)) {
                        effects.push_back(std::move(e));
                        continue;
                    }
                    if (caller_acc->balance < fee_total) {
                        e.retryable = true;
                        effects.push_back(std::move(e));
                        continue;
                    }

                    Account next = *caller_acc;
                    next.balance -= fee_total;
                    next.nonce += 1;
                    e.fee = fee_total;
                    e.fee_burn = fee_burn;
                    e.fee_tip = fee_tip;
                    e.changes.push_back(AccountChange{u->caller, next});
                    e.code_changes.emplace_back(contract_hex, u->new_code);
                    e.ok = true;
                    effects.push_back(std::move(e));
                    continue;
                }

                effects.push_back(std::move(e));
            }

            std::vector<ScheduledTx> retry;
            retry.reserve(remaining.size());

            for (const auto& e : effects) {
                if (!e.ok) {
                    if (e.retryable) {
                        auto it = std::find_if(remaining.begin(), remaining.end(), [&](const ScheduledTx& st) { return st.id == e.id; });
                        if (it != remaining.end()) {
                            retry.push_back(*it);
                        }
                    } else {
                        aborted_all.push_back(e.id);
                    }
                    continue;
                }

                bool valid = true;
                for (const auto& rid : e.read_ids) {
                    if (starts_with(rid, kAcctPrefix)) {
                        const auto id = std::string(strip_prefix(rid, kAcctPrefix));
                        const auto cur = state.get_account(id);
                        const auto snap = snap_acct[id];
                        if (!same_account_opt(cur, snap)) {
                            valid = false;
                            break;
                        }
                    } else if (starts_with(rid, kCodePrefix)) {
                        const auto ch = std::string(strip_prefix(rid, kCodePrefix));
                        const auto code = state.get_contract_code(ch);
                        const auto h = code ? crypto::sha256(std::span<const std::uint8_t>(code->data(), code->size())) : crypto::sha256(std::string_view{});
                        if (snap_code_hash[ch] != h) {
                            valid = false;
                            break;
                        }
                    }
                }
                if (!valid) {
                    auto it = std::find_if(remaining.begin(), remaining.end(), [&](const ScheduledTx& st) { return st.id == e.id; });
                    if (it != remaining.end()) {
                        retry.push_back(*it);
                    }
                    continue;
                }

                std::vector<std::pair<std::string, std::optional<Account>>> acct_changes;
                acct_changes.reserve(e.changes.size());
                for (const auto& c : e.changes) {
                    acct_changes.emplace_back(c.id, c.next);
                }

                StateDelta delta;
                if (!state.apply_batch(acct_changes, e.code_changes, e.storage_changes, delta)) {
                    aborted_all.push_back(e.id);
                    continue;
                }

                const auto next_burned = burned_fees + e.fee_burn;
                if (next_burned < burned_fees) {
                    (void)state.revert(delta);
                    aborted_all.push_back(e.id);
                    continue;
                }
                const auto next_tips = total_tips + e.fee_tip;
                if (next_tips < total_tips) {
                    (void)state.revert(delta);
                    aborted_all.push_back(e.id);
                    continue;
                }

                applied_all.push_back(e.id);
                applied_deltas.emplace_back(e.id, delta);
                fee_gas_by_id[crypto::to_hex(e.id)] = std::make_pair(e.fee, e.gas_used);

                burned_fees = next_burned;
                total_tips = next_tips;

                const auto next_gas = total_gas_used + e.gas_used;
                if (next_gas >= total_gas_used) {
                    total_gas_used = next_gas;
                }

            }

            if (retry.size() == remaining.size()) {
                for (const auto& st : retry) {
                    aborted_all.push_back(st.id);
                }
                break;
            }

            remaining = std::move(retry);
            std::sort(remaining.begin(), remaining.end(), [](const ScheduledTx& a, const ScheduledTx& b) { return a.id < b.id; });
        }

        if (!remaining.empty()) {
            for (const auto& st : remaining) {
                aborted_all.push_back(st.id);
            }
        }
    }

    std::sort(applied_all.begin(), applied_all.end());
    applied_all.erase(std::unique(applied_all.begin(), applied_all.end()), applied_all.end());
    std::sort(aborted_all.begin(), aborted_all.end());
    aborted_all.erase(std::unique(aborted_all.begin(), aborted_all.end()), aborted_all.end());

    StateDelta burn_delta;
    StateDelta base_fee_delta;
    StateDelta tip_delta;

    if (!state.update_base_fee(total_gas_used, base_fee_delta)) {
        for (auto it = applied_deltas.rbegin(); it != applied_deltas.rend(); ++it) {
            (void)state.revert(it->second);
        }
        r.applied = {};
        r.aborted = {};
        r.rejected = {};
        r.state_root = state.state_root();
        r.tx_results.clear();
        r.delta = ExecutionResult::DeltaSummary{};
        return r;
    }

    if (!state.collect_tips(total_tips, tip_delta)) {
        (void)state.revert(base_fee_delta);
        for (auto it = applied_deltas.rbegin(); it != applied_deltas.rend(); ++it) {
            (void)state.revert(it->second);
        }
        r.applied = {};
        r.aborted = {};
        r.rejected = {};
        r.state_root = state.state_root();
        r.tx_results.clear();
        r.delta = ExecutionResult::DeltaSummary{};
        return r;
    }

    if (!state.burn_fees(burned_fees, burn_delta)) {
        (void)state.revert(tip_delta);
        (void)state.revert(base_fee_delta);
        for (auto it = applied_deltas.rbegin(); it != applied_deltas.rend(); ++it) {
            (void)state.revert(it->second);
        }
        r.applied = {};
        r.aborted = {};
        r.rejected = {};
        r.state_root = state.state_root();
        r.tx_results.clear();
        r.delta = ExecutionResult::DeltaSummary{};
        return r;
    }

    r.applied = std::move(applied_all);
    r.aborted = std::move(aborted_all);
    r.state_root = state.state_root();

    {
        std::vector<std::string> acct;
        std::vector<std::string> code;
        std::vector<std::string> stor;
        std::vector<std::string> meta;

        for (const auto& [_, d] : applied_deltas) {
            for (const auto& [id, __] : d.prior_accounts) {
                acct.push_back(id);
            }
            for (const auto& [id, __] : d.prior_codes) {
                code.push_back(id);
            }
            for (const auto& [id, __] : d.prior_storage) {
                stor.push_back(id);
            }
            for (const auto& [id, __] : d.prior_meta) {
                meta.push_back(id);
            }
        }
        for (const auto& [id, __] : burn_delta.prior_meta) {
            meta.push_back(id);
        }
        for (const auto& [id, __] : tip_delta.prior_meta) {
            meta.push_back(id);
        }
        for (const auto& [id, __] : base_fee_delta.prior_meta) {
            meta.push_back(id);
        }

        auto sort_uniq = [](std::vector<std::string>& v) {
            std::sort(v.begin(), v.end());
            v.erase(std::unique(v.begin(), v.end()), v.end());
        };
        sort_uniq(acct);
        sort_uniq(code);
        sort_uniq(stor);
        sort_uniq(meta);

        r.delta = ExecutionResult::DeltaSummary{};
        r.delta.accounts = acct.size();
        r.delta.codes = code.size();
        r.delta.storage = stor.size();
        r.delta.meta = meta.size();
        r.delta.account_keys = acct;
        r.delta.code_keys = code;
        r.delta.storage_keys = stor;
        r.delta.meta_keys = meta;
    }

    {
        std::vector<crypto::Hash256> all;
        all.reserve(r.applied.size() + r.aborted.size() + r.rejected.size());
        all.insert(all.end(), r.applied.begin(), r.applied.end());
        all.insert(all.end(), r.aborted.begin(), r.aborted.end());
        all.insert(all.end(), r.rejected.begin(), r.rejected.end());
        std::sort(all.begin(), all.end());
        all.erase(std::unique(all.begin(), all.end()), all.end());

        r.tx_results.clear();
        r.tx_results.reserve(all.size());

        auto contains = [](const std::vector<crypto::Hash256>& v, const crypto::Hash256& id) {
            return std::find(v.begin(), v.end(), id) != v.end();
        };

        for (const auto& id : all) {
            ExecutionResult::TxResult tr;
            tr.id = id;
            const auto hex = crypto::to_hex(id);
            if (contains(r.rejected, id)) {
                tr.status = ExecutionResult::TxStatus::Rejected;
                tr.reason = ExecutionResult::ReasonCode::Invalid;
                tr.fee_charged = 0;
                tr.gas_used = 0;
            } else if (contains(r.applied, id)) {
                tr.status = ExecutionResult::TxStatus::Applied;
                tr.reason = ExecutionResult::ReasonCode::Ok;
                const auto it = fee_gas_by_id.find(hex);
                if (it != fee_gas_by_id.end()) {
                    tr.fee_charged = it->second.first;
                    tr.gas_used = it->second.second;
                }
            } else {
                tr.status = ExecutionResult::TxStatus::Aborted;
                tr.reason = (retryable_ids.find(hex) != retryable_ids.end()) ? ExecutionResult::ReasonCode::Retryable : ExecutionResult::ReasonCode::Aborted;
                tr.fee_charged = 0;
                tr.gas_used = 0;
            }
            r.tx_results.push_back(tr);
        }
    }

    return r;
}

}
