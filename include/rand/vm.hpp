#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "rand/sha256.hpp"

namespace randio::vm {

using Address = crypto::Hash256;

struct Bytecode final {
    std::uint32_t version{1};
    std::vector<std::uint8_t> code{};
};

struct ValidationLimits final {
    std::size_t max_code_bytes{64 * 1024};
    std::size_t max_stack_items{1024};
    std::size_t max_memory_bytes{64 * 1024};
    std::size_t max_steps{200000};
    std::size_t max_call_depth{16};
};

enum class Status : std::uint8_t {
    Ok = 0,
    Revert = 1,
    OutOfGas = 2,
    InvalidBytecode = 3,
    Trap = 4
};

struct StorageWrite final {
    Address contract{};
    crypto::Hash256 key{};
    std::vector<std::uint8_t> value{};
};

struct Event final {
    Address contract{};
    crypto::Hash256 topic{};
    std::vector<std::uint8_t> data{};
};

struct Result final {
    Status status{Status::Trap};
    std::uint64_t gas_used{0};
    std::vector<std::uint8_t> return_data{};
    std::vector<StorageWrite> writes{};
    std::vector<Event> events{};
};

struct ExecutionContext final {
    Address caller{};
    Address self{};
    std::uint64_t value{0};
    std::uint64_t gas_limit{0};
    std::size_t depth{0};
};

struct Host final {
    std::function<std::optional<std::vector<std::uint8_t>>(Address, crypto::Hash256)> storage_get;

    std::function<void(std::vector<StorageWrite>&, Address, crypto::Hash256, std::vector<std::uint8_t>)> storage_set;

    std::function<std::optional<std::vector<std::uint8_t>>(Address)> get_code;

    std::function<std::optional<crypto::Hash256>(std::string_view)> resolve_account;

    std::function<std::optional<std::uint64_t>(crypto::Hash256)> account_balance;
};

class VM final {
public:
    struct Options final {
        ValidationLimits limits{};
    };

    explicit VM(Options opt);

    [[nodiscard]] bool validate(const Bytecode& bc) const;

    [[nodiscard]] Result execute(const Bytecode& bc,
                                const ExecutionContext& ctx,
                                Host& host,
                                std::span<const std::uint8_t> input) const;

    [[nodiscard]] static std::optional<Bytecode> decode_bytecode(std::span<const std::uint8_t> bytes);
    [[nodiscard]] static std::vector<std::uint8_t> encode_bytecode(const Bytecode& bc);

    enum class Op : std::uint8_t {
        STOP = 0x00,
        REVERT = 0x01,

        PUSH_U64 = 0x10,
        PUSH_BYTES32 = 0x11,
        POP = 0x12,
        DUP = 0x13,
        SWAP = 0x14,

        ADD = 0x20,
        SUB = 0x21,
        MUL = 0x22,
        DIV = 0x23,
        MOD = 0x24,
        EQ = 0x25,
        LT = 0x26,
        GT = 0x27,

        JMP = 0x30,
        JZ = 0x31,

        MLOAD = 0x40,
        MSTORE = 0x41,
        SHA256_MEM = 0x42,

        SLOAD = 0x50,
        SSTORE = 0x51,

        EMIT = 0x60,

        CALL = 0x70
    };

private:
    Options opt_{};

    [[nodiscard]] bool validate_(const Bytecode& bc, std::vector<std::size_t>& out_inst_offsets) const;
};

}
