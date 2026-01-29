#include "rand/vm.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace randio::vm {
namespace {

std::uint32_t read_u32_le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
           (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
}

std::uint64_t read_u64_le(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
    }
    return v;
}

std::optional<std::uint64_t> decode_u64_le(std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 8) {
        return std::nullopt;
    }
    return read_u64_le(bytes.data());
}

void append_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

bool checked_add_u64(const std::uint64_t a, const std::uint64_t b, std::uint64_t& out) {
    out = a + b;
    return out >= a;
}

bool checked_sub_u64(const std::uint64_t a, const std::uint64_t b, std::uint64_t& out) {
    if (a < b) {
        return false;
    }
    out = a - b;
    return true;
}

bool checked_mul_u64(const std::uint64_t a, const std::uint64_t b, std::uint64_t& out) {
    const unsigned __int128 p = static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b);
    if (p > static_cast<unsigned __int128>(std::numeric_limits<std::uint64_t>::max())) {
        return false;
    }
    out = static_cast<std::uint64_t>(p);
    return true;
}

struct GasMeter final {
    std::uint64_t limit{0};
    std::uint64_t used{0};

    [[nodiscard]] bool consume(const std::uint64_t g) {
        const std::uint64_t next = used + g;
        if (next < used) {
            return false;
        }
        if (next > limit) {
            return false;
        }
        used = next;
        return true;
    }
};

std::uint64_t op_gas(VM::Op op) {
    switch (op) {
    case VM::Op::STOP:
    case VM::Op::REVERT:
        return 0;
    case VM::Op::PUSH_U64:
    case VM::Op::PUSH_BYTES32:
    case VM::Op::POP:
    case VM::Op::DUP:
    case VM::Op::SWAP:
        return 1;
    case VM::Op::ADD:
    case VM::Op::SUB:
    case VM::Op::MUL:
    case VM::Op::DIV:
    case VM::Op::MOD:
    case VM::Op::EQ:
    case VM::Op::LT:
    case VM::Op::GT:
        return 2;
    case VM::Op::JMP:
    case VM::Op::JZ:
        return 3;
    case VM::Op::MLOAD:
    case VM::Op::MSTORE:
        return 3;
    case VM::Op::SHA256_MEM:
        return 50;
    case VM::Op::SLOAD:
        return 50;
    case VM::Op::SSTORE:
        return 200;
    case VM::Op::EMIT:
        return 20;
    case VM::Op::CALL:
        return 40;
    }
    return 0;
}

bool is_supported_version(const std::uint32_t v) {
    return v == 1;
}

}

VM::VM(Options opt) : opt_(opt) {}

std::optional<Bytecode> VM::decode_bytecode(const std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 8) {
        return std::nullopt;
    }
    const auto ver = read_u32_le(bytes.data());
    const auto len = read_u32_le(bytes.data() + 4);
    if (bytes.size() != 8 + static_cast<std::size_t>(len)) {
        return std::nullopt;
    }
    Bytecode bc;
    bc.version = ver;
    bc.code.assign(bytes.begin() + 8, bytes.end());
    return bc;
}

std::vector<std::uint8_t> VM::encode_bytecode(const Bytecode& bc) {
    std::vector<std::uint8_t> out;
    out.reserve(8 + bc.code.size());
    append_u32_le(out, bc.version);
    append_u32_le(out, static_cast<std::uint32_t>(bc.code.size()));
    out.insert(out.end(), bc.code.begin(), bc.code.end());
    return out;
}

bool VM::validate_(const Bytecode& bc, std::vector<std::size_t>& out_inst_offsets) const {
    out_inst_offsets.clear();

    if (!is_supported_version(bc.version)) {
        return false;
    }
    if (bc.code.size() > opt_.limits.max_code_bytes) {
        return false;
    }

    std::size_t pc = 0;
    out_inst_offsets.reserve(bc.code.size() / 2);

    while (pc < bc.code.size()) {
        out_inst_offsets.push_back(pc);
        const auto op = static_cast<Op>(bc.code[pc]);
        ++pc;
        switch (op) {
        case Op::STOP:
        case Op::REVERT:
        case Op::POP:
        case Op::DUP:
        case Op::SWAP:
        case Op::ADD:
        case Op::SUB:
        case Op::MUL:
        case Op::DIV:
        case Op::MOD:
        case Op::EQ:
        case Op::LT:
        case Op::GT:
        case Op::MLOAD:
        case Op::MSTORE:
        case Op::SHA256_MEM:
        case Op::SLOAD:
        case Op::SSTORE:
        case Op::EMIT:
            break;
        case Op::PUSH_U64:
            if (pc + 8 > bc.code.size()) {
                return false;
            }
            pc += 8;
            break;
        case Op::PUSH_BYTES32:
            if (pc + 32 > bc.code.size()) {
                return false;
            }
            pc += 32;
            break;
        case Op::JMP:
        case Op::JZ:
            if (pc + 4 > bc.code.size()) {
                return false;
            }
            pc += 4;
            break;
        case Op::CALL:
            if (pc + 32 > bc.code.size()) {
                return false;
            }
            pc += 32;
            break;
        default:
            return false;
        }
    }

    std::unordered_set<std::size_t> inst;
    inst.reserve(out_inst_offsets.size());
    for (const auto off : out_inst_offsets) {
        inst.insert(off);
    }

    pc = 0;
    while (pc < bc.code.size()) {
        const auto op = static_cast<Op>(bc.code[pc]);
        ++pc;

        if (op == Op::PUSH_U64) {
            pc += 8;
            continue;
        }
        if (op == Op::PUSH_BYTES32) {
            pc += 32;
            continue;
        }
        if (op == Op::CALL) {
            pc += 32;
            continue;
        }

        if (op == Op::JMP || op == Op::JZ) {
            const auto tgt = static_cast<std::size_t>(read_u32_le(bc.code.data() + pc));
            pc += 4;
            if (tgt >= bc.code.size()) {
                return false;
            }
            if (!inst.contains(tgt)) {
                return false;
            }
        }
    }

    return true;
}

bool VM::validate(const Bytecode& bc) const {
    std::vector<std::size_t> inst;
    return validate_(bc, inst);
}

Result VM::execute(const Bytecode& bc,
                   const ExecutionContext& ctx,
                   Host& host,
                   const std::span<const std::uint8_t> input) const {
    Result res;
    res.status = Status::Ok;

    std::vector<std::size_t> inst_offsets;
    if (!validate_(bc, inst_offsets)) {
        res.status = Status::InvalidBytecode;
        return res;
    }

    if (ctx.depth > opt_.limits.max_call_depth) {
        res.status = Status::Trap;
        return res;
    }

    GasMeter gas{ctx.gas_limit, 0};

    std::vector<std::uint64_t> stack;
    stack.reserve(opt_.limits.max_stack_items);

    std::vector<std::uint8_t> mem;
    mem.resize(opt_.limits.max_memory_bytes, 0);

    auto pop_u64 = [&]() -> std::optional<std::uint64_t> {
        if (stack.empty()) {
            return std::nullopt;
        }
        auto v = stack.back();
        stack.pop_back();
        return v;
    };

    auto push_u64 = [&](const std::uint64_t v) -> bool {
        if (stack.size() >= opt_.limits.max_stack_items) {
            return false;
        }
        stack.push_back(v);
        return true;
    };

    std::vector<StorageWrite> pending_writes;
    std::vector<Event> events;

    std::size_t pc = 0;
    std::size_t steps = 0;

    while (pc < bc.code.size()) {
        if (steps++ > opt_.limits.max_steps) {
            res.status = Status::Trap;
            break;
        }

        const auto op = static_cast<Op>(bc.code[pc]);
        if (!gas.consume(op_gas(op))) {
            res.status = Status::OutOfGas;
            pending_writes.clear();
            events.clear();
            break;
        }
        ++pc;

        switch (op) {
        case Op::STOP:
            res.status = Status::Ok;
            pc = bc.code.size();
            break;
        case Op::REVERT:
            res.status = Status::Revert;
            pending_writes.clear();
            events.clear();
            pc = bc.code.size();
            break;
        case Op::PUSH_U64: {
            const auto v = read_u64_le(bc.code.data() + pc);
            pc += 8;
            if (!push_u64(v)) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::PUSH_BYTES32: {
            if (stack.size() + 4 > opt_.limits.max_stack_items) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            std::array<std::uint8_t, 32> buf{};
            std::copy(bc.code.begin() + static_cast<std::ptrdiff_t>(pc),
                      bc.code.begin() + static_cast<std::ptrdiff_t>(pc + 32),
                      buf.begin());
            pc += 32;
            for (int i = 0; i < 4; ++i) {
                if (!push_u64(read_u64_le(buf.data() + (8 * i)))) {
                    res.status = Status::Trap;
                    pending_writes.clear();
                    events.clear();
                    pc = bc.code.size();
                    break;
                }
            }
            break;
        }
        case Op::POP: {
            if (!pop_u64()) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::DUP: {
            if (stack.empty()) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            if (!push_u64(stack.back())) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::SWAP: {
            if (stack.size() < 2) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            std::swap(stack[stack.size() - 1], stack[stack.size() - 2]);
            break;
        }
        case Op::ADD: {
            const auto b = pop_u64();
            const auto a = pop_u64();
            std::uint64_t out = 0;
            if (!a || !b || !checked_add_u64(*a, *b, out) || !push_u64(out)) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::SUB: {
            const auto b = pop_u64();
            const auto a = pop_u64();
            std::uint64_t out = 0;
            if (!a || !b || !checked_sub_u64(*a, *b, out) || !push_u64(out)) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::MUL: {
            const auto b = pop_u64();
            const auto a = pop_u64();
            std::uint64_t out = 0;
            if (!a || !b || !checked_mul_u64(*a, *b, out) || !push_u64(out)) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::DIV: {
            const auto b = pop_u64();
            const auto a = pop_u64();
            if (!a || !b || *b == 0 || !push_u64((*a) / (*b))) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::MOD: {
            const auto b = pop_u64();
            const auto a = pop_u64();
            if (!a || !b || *b == 0 || !push_u64((*a) % (*b))) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::EQ: {
            const auto b = pop_u64();
            const auto a = pop_u64();
            if (!a || !b || !push_u64((*a == *b) ? 1 : 0)) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::LT: {
            const auto b = pop_u64();
            const auto a = pop_u64();
            if (!a || !b || !push_u64((*a < *b) ? 1 : 0)) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::GT: {
            const auto b = pop_u64();
            const auto a = pop_u64();
            if (!a || !b || !push_u64((*a > *b) ? 1 : 0)) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::JMP: {
            const auto tgt = static_cast<std::size_t>(read_u32_le(bc.code.data() + pc));
            pc = tgt;
            break;
        }
        case Op::JZ: {
            const auto tgt = static_cast<std::size_t>(read_u32_le(bc.code.data() + pc));
            pc += 4;
            const auto cond = pop_u64();
            if (!cond) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            if (*cond == 0) {
                pc = tgt;
            }
            break;
        }
        case Op::MLOAD: {
            const auto off = pop_u64();
            if (!off || *off + 8 > mem.size()) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            const auto v = read_u64_le(mem.data() + static_cast<std::size_t>(*off));
            if (!push_u64(v)) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::MSTORE: {
            const auto off = pop_u64();
            const auto v = pop_u64();
            if (!off || !v || *off + 8 > mem.size()) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            const auto o = static_cast<std::size_t>(*off);
            for (int i = 0; i < 8; ++i) {
                mem[o + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((*v >> (8u * i)) & 0xFFu);
            }
            break;
        }
        case Op::SHA256_MEM: {
            const auto len = pop_u64();
            const auto off = pop_u64();
            const auto dst = pop_u64();
            if (!len || !off || !dst) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            const auto o = static_cast<std::size_t>(*off);
            const auto l = static_cast<std::size_t>(*len);
            const auto d = static_cast<std::size_t>(*dst);
            if (o + l > mem.size() || d + 32 > mem.size()) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            const auto h = crypto::sha256(std::span<const std::uint8_t>(mem.data() + o, l));
            std::copy(h.begin(), h.end(), mem.begin() + static_cast<std::ptrdiff_t>(d));
            break;
        }
        case Op::SLOAD: {
            if (!host.storage_get) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            std::array<std::uint8_t, 32> key{};
            for (int i = 3; i >= 0; --i) {
                const auto w = pop_u64();
                if (!w) {
                    res.status = Status::Trap;
                    pending_writes.clear();
                    events.clear();
                    pc = bc.code.size();
                    goto end_exec;
                }
                const auto off = static_cast<std::size_t>(i) * 8;
                for (int j = 0; j < 8; ++j) {
                    key[off + static_cast<std::size_t>(j)] = static_cast<std::uint8_t>((*w >> (8u * j)) & 0xFFu);
                }
            }
            crypto::Hash256 k{};
            std::copy(key.begin(), key.end(), k.begin());
            const auto v = host.storage_get(ctx.self, k);
            std::uint64_t outv = 0;
            if (v && !v->empty()) {
                const auto dv = decode_u64_le(std::span<const std::uint8_t>(v->data(), v->size()));
                if (!dv) {
                    res.status = Status::Trap;
                    pending_writes.clear();
                    events.clear();
                    pc = bc.code.size();
                    break;
                }
                outv = *dv;
            }
            if (!push_u64(outv)) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
            }
            break;
        }
        case Op::SSTORE: {
            if (!host.storage_set) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            const auto v = pop_u64();
            if (!v) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            std::vector<std::uint8_t> val;
            val.reserve(8);
            append_u64_le(val, *v);

            std::array<std::uint8_t, 32> key{};
            for (int i = 3; i >= 0; --i) {
                const auto w = pop_u64();
                if (!w) {
                    res.status = Status::Trap;
                    pending_writes.clear();
                    events.clear();
                    pc = bc.code.size();
                    goto end_exec;
                }
                const auto off = static_cast<std::size_t>(i) * 8;
                for (int j = 0; j < 8; ++j) {
                    key[off + static_cast<std::size_t>(j)] = static_cast<std::uint8_t>((*w >> (8u * j)) & 0xFFu);
                }
            }
            crypto::Hash256 k{};
            std::copy(key.begin(), key.end(), k.begin());
            host.storage_set(pending_writes, ctx.self, k, std::move(val));
            break;
        }
        case Op::EMIT: {
            const auto len = pop_u64();
            const auto off = pop_u64();
            if (!len || !off) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            std::array<std::uint8_t, 32> topic{};
            for (int i = 3; i >= 0; --i) {
                const auto w = pop_u64();
                if (!w) {
                    res.status = Status::Trap;
                    pending_writes.clear();
                    events.clear();
                    pc = bc.code.size();
                    goto end_exec;
                }
                const auto to = static_cast<std::size_t>(i) * 8;
                for (int j = 0; j < 8; ++j) {
                    topic[to + static_cast<std::size_t>(j)] = static_cast<std::uint8_t>((*w >> (8u * j)) & 0xFFu);
                }
            }
            crypto::Hash256 t{};
            std::copy(topic.begin(), topic.end(), t.begin());
            const auto o = static_cast<std::size_t>(*off);
            const auto l = static_cast<std::size_t>(*len);
            if (o + l > mem.size()) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            Event ev;
            ev.contract = ctx.self;
            ev.topic = t;
            ev.data.assign(mem.begin() + static_cast<std::ptrdiff_t>(o),
                           mem.begin() + static_cast<std::ptrdiff_t>(o + l));
            events.push_back(std::move(ev));
            break;
        }
        case Op::CALL: {
            if (!host.get_code) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            std::array<std::uint8_t, 32> addr{};
            std::copy(bc.code.begin() + static_cast<std::ptrdiff_t>(pc),
                      bc.code.begin() + static_cast<std::ptrdiff_t>(pc + 32),
                      addr.begin());
            pc += 32;

            Address callee{};
            std::copy(addr.begin(), addr.end(), callee.begin());

            const auto gas_for_call = pop_u64();
            if (!gas_for_call) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            if (*gas_for_call > (ctx.gas_limit - gas.used)) {
                res.status = Status::OutOfGas;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }

            const auto code_bytes = host.get_code(callee);
            if (!code_bytes) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            const auto callee_bc = decode_bytecode(std::span<const std::uint8_t>(code_bytes->data(), code_bytes->size()));
            if (!callee_bc) {
                res.status = Status::Trap;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }

            ExecutionContext cctx;
            cctx.caller = ctx.self;
            cctx.self = callee;
            cctx.value = 0;
            cctx.gas_limit = *gas_for_call;
            cctx.depth = ctx.depth + 1;

            const VM nested(opt_);
            auto r2 = nested.execute(*callee_bc, cctx, host, input);
            const auto next_used = gas.used + r2.gas_used;
            if (next_used < gas.used) {
                res.status = Status::OutOfGas;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }
            gas.used = next_used;
            if (gas.used > gas.limit) {
                res.status = Status::OutOfGas;
                pending_writes.clear();
                events.clear();
                pc = bc.code.size();
                break;
            }

            if (r2.status != Status::Ok) {
                if (!push_u64(0)) {
                    res.status = Status::Trap;
                    pending_writes.clear();
                    events.clear();
                    pc = bc.code.size();
                    break;
                }
            } else {
                if (!push_u64(1)) {
                    res.status = Status::Trap;
                    pending_writes.clear();
                    events.clear();
                    pc = bc.code.size();
                    break;
                }
                pending_writes.insert(pending_writes.end(), r2.writes.begin(), r2.writes.end());
                events.insert(events.end(), r2.events.begin(), r2.events.end());
            }
            break;
        }
        }

        if (res.status == Status::Trap || res.status == Status::OutOfGas || res.status == Status::Revert) {
            break;
        }
    }

end_exec:

    res.gas_used = gas.used;
    res.writes = std::move(pending_writes);
    res.events = std::move(events);
    if (res.status == Status::Trap) {
        res.writes.clear();
        res.events.clear();
    }
    return res;
}

}
