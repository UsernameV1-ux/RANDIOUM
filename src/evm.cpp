#include "rand/evm/evm.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace randio::module107 {

namespace {

[[nodiscard]] constexpr std::uint64_t rotl64(const std::uint64_t x, const unsigned r) {
    return (r == 0) ? x : ((x << r) | (x >> (64u - r)));
}

[[nodiscard]] constexpr std::uint64_t load_le64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * static_cast<unsigned>(i)));
    }
    return v;
}

void store_le64(std::uint8_t* p, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::uint8_t>((v >> (8u * static_cast<unsigned>(i))) & 0xFFu);
    }
}

void keccak_f1600(std::array<std::uint64_t, 25>& a) {
    static constexpr std::uint64_t rc[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
    };

    static constexpr unsigned rot[25] = {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    };

    static constexpr int piln[25] = {
        0, 10, 20, 5, 15,
        16, 1, 11, 21, 6,
        7, 17, 2, 12, 22,
        23, 8, 18, 3, 13,
        14, 24, 9, 19, 4,
    };

    for (int round = 0; round < 24; ++round) {
        std::uint64_t c[5] = {0, 0, 0, 0, 0};
        for (int x = 0; x < 5; ++x) {
            c[x] = a[static_cast<std::size_t>(x)] ^ a[static_cast<std::size_t>(x + 5)] ^ a[static_cast<std::size_t>(x + 10)] ^
                   a[static_cast<std::size_t>(x + 15)] ^ a[static_cast<std::size_t>(x + 20)];
        }
        std::uint64_t d[5] = {0, 0, 0, 0, 0};
        for (int x = 0; x < 5; ++x) {
            d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        }
        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                a[static_cast<std::size_t>(x + 5 * y)] ^= d[x];
            }
        }

        std::array<std::uint64_t, 25> b{};
        for (int i = 0; i < 25; ++i) {
            b[static_cast<std::size_t>(piln[i])] = rotl64(a[static_cast<std::size_t>(i)], rot[static_cast<std::size_t>(i)]);
        }

        for (int y = 0; y < 5; ++y) {
            for (int x = 0; x < 5; ++x) {
                a[static_cast<std::size_t>(x + 5 * y)] = b[static_cast<std::size_t>(x + 5 * y)] ^
                                                       ((~b[static_cast<std::size_t>(((x + 1) % 5) + 5 * y)]) &
                                                        b[static_cast<std::size_t>(((x + 2) % 5) + 5 * y)]);
            }
        }

        a[0] ^= rc[static_cast<std::size_t>(round)];
    }
}

[[nodiscard]] bool add_u64_carry(const std::uint64_t a, const std::uint64_t b, std::uint64_t& out, std::uint64_t& carry) {
    const std::uint64_t s1 = a + b;
    const bool c1 = (s1 < a);
    const std::uint64_t s2 = s1 + carry;
    const bool c2 = (s2 < s1);
    out = s2;
    carry = (c1 || c2) ? 1 : 0;
    return (c1 || c2);
}

[[nodiscard]] bool sub_u64_borrow(const std::uint64_t a, const std::uint64_t b, std::uint64_t& out, std::uint64_t& borrow) {
    const std::uint64_t t = a - b;
    const bool b1 = (a < b);
    const std::uint64_t t2 = t - borrow;
    const bool b2 = (t < borrow);
    out = t2;
    borrow = (b1 || b2) ? 1 : 0;
    return (b1 || b2);
}

[[nodiscard]] std::optional<std::size_t> u256_to_size_checked(const U256& v) {
    const auto u = v.to_u64_exact();
    if (!u.has_value()) {
        return std::nullopt;
    }
    if (*u > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(*u);
}

[[nodiscard]] bool get_bit(const U256& v, const std::size_t bit) {
    const std::size_t word = bit / 64;
    const std::size_t off = bit % 64;
    if (word >= 4) {
        return false;
    }
    return ((v.w[word] >> off) & 1u) != 0u;
}

void set_bit(U256& v, const std::size_t bit) {
    const std::size_t word = bit / 64;
    const std::size_t off = bit % 64;
    if (word >= 4) {
        return;
    }
    v.w[word] |= (1ULL << off);
}

[[nodiscard]] U256 shl1(const U256& v) {
    U256 out{};
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        const std::uint64_t next = (v.w[i] >> 63u) & 1u;
        out.w[i] = (v.w[i] << 1u) | carry;
        carry = next;
    }
    return out;
}

[[nodiscard]] U256 shr1(const U256& v) {
    U256 out{};
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        const std::size_t idx = 3 - i;
        const std::uint64_t next = (v.w[idx] & 1u);
        out.w[idx] = (v.w[idx] >> 1u) | (carry << 63u);
        carry = next;
    }
    return out;
}

[[nodiscard]] std::optional<U256> checked_add_mem_size(const std::size_t a, const std::size_t b) {
    if (a > (std::numeric_limits<std::size_t>::max)() - b) {
        return std::nullopt;
    }
    return U256::from_u64(static_cast<std::uint64_t>(a + b));
}

} // namespace

U256 U256::zero() {
    return U256{};
}

U256 U256::one() {
    U256 v{};
    v.w[0] = 1;
    return v;
}

U256 U256::from_u64(const std::uint64_t v) {
    U256 out{};
    out.w[0] = v;
    return out;
}

U256 U256::from_be32(std::span<const std::uint8_t, 32> be) {
    U256 out{};
    for (int i = 0; i < 4; ++i) {
        std::uint64_t w = 0;
        for (int j = 0; j < 8; ++j) {
            w = (w << 8u) | static_cast<std::uint64_t>(be[static_cast<std::size_t>(i * 8 + j)]);
        }
        out.w[3 - static_cast<std::size_t>(i)] = w;
    }
    return out;
}

Bytes32 U256::to_be32() const {
    Bytes32 out{};
    for (int i = 0; i < 4; ++i) {
        const std::uint64_t w64 = w[3 - static_cast<std::size_t>(i)];
        for (int j = 0; j < 8; ++j) {
            out[static_cast<std::size_t>(i * 8 + j)] = static_cast<std::uint8_t>((w64 >> (56u - 8u * static_cast<unsigned>(j))) & 0xFFu);
        }
    }
    return out;
}

bool U256::is_zero() const {
    return w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0;
}

std::optional<std::uint64_t> U256::to_u64_exact() const {
    if (w[1] != 0 || w[2] != 0 || w[3] != 0) {
        return std::nullopt;
    }
    return w[0];
}

bool operator==(const U256& a, const U256& b) {
    return a.w == b.w;
}

bool operator!=(const U256& a, const U256& b) {
    return !(a == b);
}

bool operator<(const U256& a, const U256& b) {
    for (std::size_t i = 0; i < 4; ++i) {
        const std::size_t idx = 3 - i;
        if (a.w[idx] < b.w[idx]) {
            return true;
        }
        if (a.w[idx] > b.w[idx]) {
            return false;
        }
    }
    return false;
}

bool operator>(const U256& a, const U256& b) {
    return b < a;
}

U256 add_mod2_256(const U256& a, const U256& b) {
    U256 out{};
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        (void)add_u64_carry(a.w[i], b.w[i], out.w[i], carry);
    }
    return out;
}

U256 sub_mod2_256(const U256& a, const U256& b) {
    U256 out{};
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        (void)sub_u64_borrow(a.w[i], b.w[i], out.w[i], borrow);
    }
    return out;
}

U256 mul_mod2_256(const U256& a, const U256& b) {
    U256 out{};

    for (std::size_t i = 0; i < 4; ++i) {
        unsigned __int128 carry = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            if (i + j >= 4) {
                break;
            }
            const unsigned __int128 cur = static_cast<unsigned __int128>(out.w[i + j]);
            const unsigned __int128 prod = static_cast<unsigned __int128>(a.w[i]) * static_cast<unsigned __int128>(b.w[j]);
            const unsigned __int128 sum = cur + prod + carry;
            out.w[i + j] = static_cast<std::uint64_t>(sum);
            carry = (sum >> 64u);
        }
    }

    return out;
}

U256 div_u256(const U256& a, const U256& b) {
    if (b.is_zero()) {
        return U256::zero();
    }

    if (a < b) {
        return U256::zero();
    }

    U256 q{};
    U256 r{};

    for (int bit = 255; bit >= 0; --bit) {
        r = shl1(r);
        if (get_bit(a, static_cast<std::size_t>(bit))) {
            r.w[0] |= 1ULL;
        }
        if (!(r < b)) {
            r = sub_mod2_256(r, b);
            set_bit(q, static_cast<std::size_t>(bit));
        }
    }

    return q;
}

U256 mod_u256(const U256& a, const U256& b) {
    if (b.is_zero()) {
        return U256::zero();
    }

    if (a < b) {
        return a;
    }

    U256 r{};

    for (int bit = 255; bit >= 0; --bit) {
        r = shl1(r);
        if (get_bit(a, static_cast<std::size_t>(bit))) {
            r.w[0] |= 1ULL;
        }
        if (!(r < b)) {
            r = sub_mod2_256(r, b);
        }
    }

    return r;
}

U256 bit_and(const U256& a, const U256& b) {
    U256 out{};
    for (std::size_t i = 0; i < 4; ++i) {
        out.w[i] = a.w[i] & b.w[i];
    }
    return out;
}

U256 bit_or(const U256& a, const U256& b) {
    U256 out{};
    for (std::size_t i = 0; i < 4; ++i) {
        out.w[i] = a.w[i] | b.w[i];
    }
    return out;
}

U256 bit_xor(const U256& a, const U256& b) {
    U256 out{};
    for (std::size_t i = 0; i < 4; ++i) {
        out.w[i] = a.w[i] ^ b.w[i];
    }
    return out;
}

Bytes32 keccak256(std::span<const std::uint8_t> bytes) {
    static constexpr std::size_t rate = 136;

    std::array<std::uint64_t, 25> st{};
    std::array<std::uint8_t, rate> block{};

    std::size_t off = 0;
    while (off + rate <= bytes.size()) {
        for (std::size_t i = 0; i < rate; ++i) {
            block[i] = bytes[off + i];
        }
        for (std::size_t i = 0; i < rate / 8; ++i) {
            st[i] ^= load_le64(block.data() + 8 * i);
        }
        keccak_f1600(st);
        off += rate;
    }

    block.fill(0);
    const std::size_t rem = bytes.size() - off;
    for (std::size_t i = 0; i < rem; ++i) {
        block[i] = bytes[off + i];
    }

    block[rem] ^= 0x01u;
    block[rate - 1] ^= 0x80u;

    for (std::size_t i = 0; i < rate / 8; ++i) {
        st[i] ^= load_le64(block.data() + 8 * i);
    }
    keccak_f1600(st);

    Bytes32 out{};
    for (std::size_t i = 0; i < 4; ++i) {
        std::uint8_t tmp[8];
        store_le64(tmp, st[i]);
        for (std::size_t j = 0; j < 8; ++j) {
            out[i * 8 + j] = tmp[j];
        }
    }

    return out;
}

EVM::EVM(Options opt)
    : opt_(std::move(opt)) {}

namespace {

[[nodiscard]] bool build_jumpdests(std::span<const std::uint8_t> code, std::unordered_set<std::size_t>& out) {
    out.clear();
    if (code.size() > 1024 * 1024) {
        return false;
    }

    std::size_t pc = 0;
    while (pc < code.size()) {
        const auto op = code[pc];
        if (op == 0x5b) {
            out.insert(pc);
            pc += 1;
            continue;
        }
        if (op >= 0x60 && op <= 0x7f) {
            const std::size_t n = static_cast<std::size_t>(op - 0x5f);
            if (pc + 1 + n > code.size()) {
                return false;
            }
            pc += 1 + n;
            continue;
        }
        pc += 1;
    }

    return true;
}

[[nodiscard]] std::optional<U256> pop(std::vector<U256>& st) {
    if (st.empty()) {
        return std::nullopt;
    }
    const auto v = st.back();
    st.pop_back();
    return v;
}

struct Pop2 final {
    U256 x{};
    U256 y{};
};

[[nodiscard]] std::optional<Pop2> pop2(std::vector<U256>& st) {
    const auto x = pop(st);
    const auto y = pop(st);
    if (!x || !y) {
        return std::nullopt;
    }
    Pop2 p;
    p.x = *x;
    p.y = *y;
    return p;
}

[[nodiscard]] bool push(std::vector<U256>& st, const U256& v, const std::size_t max_items) {
    if (st.size() >= max_items) {
        return false;
    }
    st.push_back(v);
    return true;
}

[[nodiscard]] bool charge(std::uint64_t& gas_used, const std::uint64_t gas_limit, const std::uint64_t cost) {
    if (gas_used > gas_limit) {
        return false;
    }
    if (cost > gas_limit - gas_used) {
        return false;
    }
    gas_used += cost;
    return true;
}

[[nodiscard]] bool ensure_mem(std::vector<std::uint8_t>& mem, const std::size_t want, const std::size_t max) {
    if (want > max) {
        return false;
    }
    if (mem.size() < want) {
        mem.resize(want, 0);
    }
    return true;
}

[[nodiscard]] std::optional<std::size_t> add_sz_checked(const std::size_t a, const std::size_t b) {
    if (a > (std::numeric_limits<std::size_t>::max)() - b) {
        return std::nullopt;
    }
    return a + b;
}

[[nodiscard]] U256 u256_from_bool(const bool v) {
    return U256::from_u64(v ? 1 : 0);
}

[[nodiscard]] U256 u256_from_bytes32_be(const Bytes32& be) {
    return U256::from_be32(std::span<const std::uint8_t, 32>(be.data(), be.size()));
}

[[nodiscard]] Bytes32 u256_to_bytes32_be(const U256& v) {
    return v.to_be32();
}

void mstore_be32(std::vector<std::uint8_t>& mem, const std::size_t off, const Bytes32& be) {
    for (std::size_t i = 0; i < 32; ++i) {
        mem[off + i] = be[i];
    }
}

struct Bytes32Hash final {
    [[nodiscard]] std::size_t operator()(const Bytes32& b) const noexcept {
        std::size_t h = 1469598103934665603ULL;
        for (std::size_t i = 0; i < b.size(); ++i) {
            h ^= static_cast<std::size_t>(b[i]);
            h *= 1099511628211ULL;
        }
        return h;
    }
};

[[nodiscard]] Bytes32 mload_be32(const std::vector<std::uint8_t>& mem, const std::size_t off) {
    Bytes32 out{};
    for (std::size_t i = 0; i < 32; ++i) {
        out[i] = mem[off + i];
    }
    return out;
}

} // namespace

Result EVM::execute(std::span<const std::uint8_t> code,
                    const ExecutionContext& ctx,
                    Host& host,
                    std::span<const std::uint8_t> calldata) const {
    Result res;

    if (code.size() > opt_.limits.max_code_bytes) {
        res.status = Status::InvalidCode;
        return res;
    }

    std::unordered_set<std::size_t> jumpdests;
    if (!build_jumpdests(code, jumpdests)) {
        res.status = Status::InvalidCode;
        return res;
    }

    std::vector<U256> stack;
    stack.reserve(128);
    std::vector<std::uint8_t> mem;
    mem.reserve(256);

    std::vector<StorageWrite> pending_writes;
    pending_writes.reserve(32);
    std::unordered_map<Bytes32, Bytes32, Bytes32Hash> overlay;

    std::size_t pc = 0;
    std::uint64_t gas_used = 0;
    std::size_t steps = 0;

    auto trap = [&]() {
        res.status = Status::Trap;
        res.gas_used = gas_used;
    };

    auto out_of_gas = [&]() {
        res.status = Status::OutOfGas;
        res.gas_used = gas_used;
    };

    auto do_return = [&](const Status st) {
        const auto off_v = pop(stack);
        const auto size_v = pop(stack);
        if (!off_v || !size_v) {
            trap();
            return;
        }
        const auto off_sz = u256_to_size_checked(*off_v);
        const auto size_sz = u256_to_size_checked(*size_v);
        if (!off_sz || !size_sz) {
            trap();
            return;
        }
        const auto end_opt = add_sz_checked(*off_sz, *size_sz);
        if (!end_opt) {
            trap();
            return;
        }
        if (!ensure_mem(mem, *end_opt, opt_.limits.max_memory_bytes)) {
            out_of_gas();
            return;
        }
        res.return_data.assign(mem.begin() + static_cast<std::ptrdiff_t>(*off_sz),
                               mem.begin() + static_cast<std::ptrdiff_t>(*end_opt));
        res.status = st;
        res.gas_used = gas_used;
    };

    auto finalize = [&]() -> Result {
        if (res.status == Status::Ok) {
            if (!host.sstore && (!pending_writes.empty())) {
                res.status = Status::Trap;
            } else {
                for (const auto& w : pending_writes) {
                    host.sstore(ctx.self, w.key, w.value);
                }
                res.writes = pending_writes;
            }
        }
        res.gas_used = gas_used;
        return res;
    };

    while (pc < code.size()) {
        if (steps >= opt_.limits.max_steps) {
            out_of_gas();
            return res;
        }
        steps += 1;

        const std::uint8_t op = code[pc];

        if (op >= 0x60 && op <= 0x7f) {
            const std::size_t n = static_cast<std::size_t>(op - 0x5f);
            if (pc + 1 + n > code.size()) {
                res.status = Status::InvalidCode;
                res.gas_used = gas_used;
                return res;
            }
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            Bytes32 be{};
            const std::size_t start = 32 - n;
            for (std::size_t i = 0; i < n; ++i) {
                be[start + i] = code[pc + 1 + i];
            }
            if (!push(stack, u256_from_bytes32_be(be), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1 + n;
            continue;
        }

        if (op >= 0x80 && op <= 0x8f) {
            const std::size_t n = static_cast<std::size_t>(op - 0x7f);
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            if (n == 0 || stack.size() < n) {
                trap();
                return res;
            }
            if (!push(stack, stack[stack.size() - n], opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            continue;
        }

        if (op >= 0x90 && op <= 0x9f) {
            const std::size_t n = static_cast<std::size_t>(op - 0x8f);
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            if (n == 0 || stack.size() < n + 1) {
                trap();
                return res;
            }
            std::swap(stack[stack.size() - 1], stack[stack.size() - 1 - n]);
            pc += 1;
            continue;
        }

        switch (op) {
        case 0x00: { // STOP
            if (!charge(gas_used, ctx.gas_limit, 0)) {
                out_of_gas();
                return finalize();
            }
            res.status = Status::Ok;
            return finalize();
        }
        case 0x01: { // ADD
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, add_mod2_256(p->y, p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x02: { // MUL
            if (!charge(gas_used, ctx.gas_limit, 5)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, mul_mod2_256(p->y, p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x03: { // SUB
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, sub_mod2_256(p->y, p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x04: { // DIV
            if (!charge(gas_used, ctx.gas_limit, 5)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, div_u256(p->y, p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x06: { // MOD
            if (!charge(gas_used, ctx.gas_limit, 5)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, mod_u256(p->y, p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x10: { // LT
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, u256_from_bool(p->y < p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x11: { // GT
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, u256_from_bool(p->y > p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x14: { // EQ
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, u256_from_bool(p->y == p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x15: { // ISZERO
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto a = pop(stack);
            if (!a) {
                trap();
                return res;
            }
            if (!push(stack, u256_from_bool(a->is_zero()), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x16: { // AND
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, bit_and(p->y, p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x17: { // OR
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, bit_or(p->y, p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x18: { // XOR
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto p = pop2(stack);
            if (!p) {
                trap();
                return res;
            }
            if (!push(stack, bit_xor(p->y, p->x), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x20: { // SHA3
            const auto off_v = pop(stack);
            const auto size_v = pop(stack);
            if (!off_v || !size_v) {
                trap();
                return res;
            }
            const auto off_sz = u256_to_size_checked(*off_v);
            const auto size_sz = u256_to_size_checked(*size_v);
            if (!off_sz || !size_sz) {
                trap();
                return res;
            }
            const auto end_opt = add_sz_checked(*off_sz, *size_sz);
            if (!end_opt) {
                trap();
                return res;
            }
            const std::uint64_t words = static_cast<std::uint64_t>((*size_sz + 31) / 32);
            const std::uint64_t cost = 30 + 6 * words;
            if (!charge(gas_used, ctx.gas_limit, cost)) {
                out_of_gas();
                return res;
            }
            if (!ensure_mem(mem, *end_opt, opt_.limits.max_memory_bytes)) {
                out_of_gas();
                return res;
            }
            const auto h = keccak256(std::span<const std::uint8_t>(mem.data() + *off_sz, *size_sz));
            if (!push(stack, u256_from_bytes32_be(h), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x35: { // CALLDATALOAD
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto off_v = pop(stack);
            if (!off_v) {
                trap();
                return res;
            }
            Bytes32 be{};
            const auto off_u64 = off_v->to_u64_exact();
            if (off_u64.has_value()) {
                const std::size_t off_sz = static_cast<std::size_t>(*off_u64);
                for (std::size_t i = 0; i < 32; ++i) {
                    const std::size_t idx = off_sz + i;
                    if (idx < calldata.size()) {
                        be[i] = calldata[idx];
                    } else {
                        be[i] = 0;
                    }
                }
            }
            if (!push(stack, u256_from_bytes32_be(be), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x36: { // CALLDATASIZE
            if (!charge(gas_used, ctx.gas_limit, 2)) {
                out_of_gas();
                return res;
            }
            if (!push(stack, U256::from_u64(static_cast<std::uint64_t>(calldata.size())), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x37: { // CALLDATACOPY
            const auto dst_v = pop(stack);
            const auto src_v = pop(stack);
            const auto size_v = pop(stack);
            if (!dst_v || !src_v || !size_v) {
                trap();
                return res;
            }
            const auto dst_sz = u256_to_size_checked(*dst_v);
            const auto src_sz = u256_to_size_checked(*src_v);
            const auto size_sz = u256_to_size_checked(*size_v);
            if (!dst_sz || !src_sz || !size_sz) {
                trap();
                return res;
            }
            const auto end_opt = add_sz_checked(*dst_sz, *size_sz);
            if (!end_opt) {
                trap();
                return res;
            }
            const std::uint64_t words = static_cast<std::uint64_t>((*size_sz + 31) / 32);
            const std::uint64_t cost = 3 + 3 * words;
            if (!charge(gas_used, ctx.gas_limit, cost)) {
                out_of_gas();
                return res;
            }
            if (!ensure_mem(mem, *end_opt, opt_.limits.max_memory_bytes)) {
                out_of_gas();
                return res;
            }
            for (std::size_t i = 0; i < *size_sz; ++i) {
                const std::size_t sidx = *src_sz + i;
                mem[*dst_sz + i] = (sidx < calldata.size()) ? calldata[sidx] : 0;
            }
            pc += 1;
            break;
        }
        case 0x50: { // POP
            if (!charge(gas_used, ctx.gas_limit, 2)) {
                out_of_gas();
                return res;
            }
            const auto a = pop(stack);
            if (!a) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x51: { // MLOAD
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto off_v = pop(stack);
            if (!off_v) {
                trap();
                return res;
            }
            const auto off_sz = u256_to_size_checked(*off_v);
            if (!off_sz) {
                trap();
                return res;
            }
            const auto end_opt = add_sz_checked(*off_sz, 32);
            if (!end_opt) {
                trap();
                return res;
            }
            if (!ensure_mem(mem, *end_opt, opt_.limits.max_memory_bytes)) {
                out_of_gas();
                return res;
            }
            const auto be = mload_be32(mem, *off_sz);
            if (!push(stack, u256_from_bytes32_be(be), opt_.limits.max_stack_items)) {
                trap();
                return res;
            }
            pc += 1;
            break;
        }
        case 0x52: { // MSTORE
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto off_v = pop(stack);
            const auto val_v = pop(stack);
            if (!off_v || !val_v) {
                trap();
                return res;
            }
            const auto off_sz = u256_to_size_checked(*off_v);
            if (!off_sz) {
                trap();
                return res;
            }
            const auto end_opt = add_sz_checked(*off_sz, 32);
            if (!end_opt) {
                trap();
                return res;
            }
            if (!ensure_mem(mem, *end_opt, opt_.limits.max_memory_bytes)) {
                out_of_gas();
                return res;
            }
            const auto be = u256_to_bytes32_be(*val_v);
            mstore_be32(mem, *off_sz, be);
            pc += 1;
            break;
        }
        case 0x53: { // MSTORE8
            if (!charge(gas_used, ctx.gas_limit, 3)) {
                out_of_gas();
                return res;
            }
            const auto off_v = pop(stack);
            const auto val_v = pop(stack);
            if (!off_v || !val_v) {
                trap();
                return res;
            }
            const auto off_sz = u256_to_size_checked(*off_v);
            if (!off_sz) {
                trap();
                return res;
            }
            const auto end_opt = add_sz_checked(*off_sz, 1);
            if (!end_opt) {
                trap();
                return res;
            }
            if (!ensure_mem(mem, *end_opt, opt_.limits.max_memory_bytes)) {
                out_of_gas();
                return res;
            }
            mem[*off_sz] = static_cast<std::uint8_t>(val_v->w[0] & 0xFFu);
            pc += 1;
            break;
        }
        case 0x54: { // SLOAD
            if (!charge(gas_used, ctx.gas_limit, 50)) {
                out_of_gas();
                return finalize();
            }
            const auto key_v = pop(stack);
            if (!key_v) {
                trap();
                return finalize();
            }
            if (!host.sload) {
                trap();
                return finalize();
            }
            const auto key = u256_to_bytes32_be(*key_v);
            Bytes32 outv{};
            {
                const auto it = overlay.find(key);
                if (it != overlay.end()) {
                    outv = it->second;
                } else {
                    const auto val = host.sload(ctx.self, key);
                    if (val.has_value()) {
                        outv = *val;
                    }
                }
            }
            if (!push(stack, u256_from_bytes32_be(outv), opt_.limits.max_stack_items)) {
                trap();
                return finalize();
            }
            pc += 1;
            break;
        }
        case 0x55: { // SSTORE
            if (!charge(gas_used, ctx.gas_limit, 20000)) {
                out_of_gas();
                return finalize();
            }
            const auto key_v = pop(stack);
            const auto val_v = pop(stack);
            if (!key_v || !val_v) {
                trap();
                return finalize();
            }
            const auto key = u256_to_bytes32_be(*key_v);
            const auto val = u256_to_bytes32_be(*val_v);

            StorageWrite w;
            w.key = key;
            w.value = val;
            pending_writes.push_back(w);
            overlay[key] = val;

            pc += 1;
            break;
        }
        case 0x56: { // JUMP
            if (!charge(gas_used, ctx.gas_limit, 8)) {
                out_of_gas();
                return res;
            }
            const auto dst_v = pop(stack);
            if (!dst_v) {
                trap();
                return res;
            }
            const auto dst_sz = u256_to_size_checked(*dst_v);
            if (!dst_sz) {
                trap();
                return res;
            }
            if (*dst_sz >= code.size() || jumpdests.find(*dst_sz) == jumpdests.end()) {
                trap();
                return res;
            }
            pc = *dst_sz;
            break;
        }
        case 0x57: { // JUMPI
            if (!charge(gas_used, ctx.gas_limit, 10)) {
                out_of_gas();
                return res;
            }
            const auto dst_v = pop(stack);
            const auto cond_v = pop(stack);
            if (!dst_v || !cond_v) {
                trap();
                return res;
            }
            if (!cond_v->is_zero()) {
                const auto dst_sz = u256_to_size_checked(*dst_v);
                if (!dst_sz) {
                    trap();
                    return res;
                }
                if (*dst_sz >= code.size() || jumpdests.find(*dst_sz) == jumpdests.end()) {
                    trap();
                    return res;
                }
                pc = *dst_sz;
            } else {
                pc += 1;
            }
            break;
        }
        case 0x5b: { // JUMPDEST
            if (!charge(gas_used, ctx.gas_limit, 1)) {
                out_of_gas();
                return res;
            }
            pc += 1;
            break;
        }
        case 0xf3: { // RETURN
            if (!charge(gas_used, ctx.gas_limit, 0)) {
                out_of_gas();
                return finalize();
            }
            do_return(Status::Ok);
            return finalize();
        }
        case 0xfd: { // REVERT
            if (!charge(gas_used, ctx.gas_limit, 0)) {
                out_of_gas();
                return finalize();
            }
            do_return(Status::Revert);
            return finalize();
        }
        default:
            trap();
            return finalize();
        }
    }

    res.status = Status::Ok;
    return finalize();
}

} // namespace randio::module107
