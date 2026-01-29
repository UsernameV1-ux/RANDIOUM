#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace randio::module107 {

using Bytes32 = std::array<std::uint8_t, 32>;
using Address20 = std::array<std::uint8_t, 20>;

struct U256 final {
    std::array<std::uint64_t, 4> w{};

    [[nodiscard]] static U256 zero();
    [[nodiscard]] static U256 one();

    [[nodiscard]] static U256 from_u64(std::uint64_t v);
    [[nodiscard]] static U256 from_be32(std::span<const std::uint8_t, 32> be);

    [[nodiscard]] Bytes32 to_be32() const;

    [[nodiscard]] bool is_zero() const;
    [[nodiscard]] std::optional<std::uint64_t> to_u64_exact() const;
};

[[nodiscard]] bool operator==(const U256& a, const U256& b);
[[nodiscard]] bool operator!=(const U256& a, const U256& b);
[[nodiscard]] bool operator<(const U256& a, const U256& b);
[[nodiscard]] bool operator>(const U256& a, const U256& b);

[[nodiscard]] U256 add_mod2_256(const U256& a, const U256& b);
[[nodiscard]] U256 sub_mod2_256(const U256& a, const U256& b);
[[nodiscard]] U256 mul_mod2_256(const U256& a, const U256& b);
[[nodiscard]] U256 div_u256(const U256& a, const U256& b);
[[nodiscard]] U256 mod_u256(const U256& a, const U256& b);

[[nodiscard]] U256 bit_and(const U256& a, const U256& b);
[[nodiscard]] U256 bit_or(const U256& a, const U256& b);
[[nodiscard]] U256 bit_xor(const U256& a, const U256& b);

[[nodiscard]] Bytes32 keccak256(std::span<const std::uint8_t> bytes);

enum class Status : std::uint8_t {
    Ok = 0,
    Revert = 1,
    OutOfGas = 2,
    InvalidCode = 3,
    Trap = 4
};

struct Limits final {
    std::size_t max_code_bytes{64 * 1024};
    std::size_t max_stack_items{1024};
    std::size_t max_memory_bytes{256 * 1024};
    std::size_t max_steps{200000};
};

struct Options final {
    Limits limits{};
};

struct ExecutionContext final {
    Address20 caller{};
    Address20 self{};
    std::uint64_t gas_limit{0};
};

struct StorageWrite final {
    Bytes32 key{};
    Bytes32 value{};
};

struct Host final {
    std::function<std::optional<Bytes32>(const Address20&, const Bytes32&)> sload;
    std::function<void(const Address20&, const Bytes32&, const Bytes32&)> sstore;
};

struct Result final {
    Status status{Status::Trap};
    std::uint64_t gas_used{0};
    std::vector<std::uint8_t> return_data{};
    std::vector<StorageWrite> writes{};
};

class EVM final {
public:
    explicit EVM(Options opt);

    [[nodiscard]] Result execute(std::span<const std::uint8_t> code,
                                const ExecutionContext& ctx,
                                Host& host,
                                std::span<const std::uint8_t> calldata) const;

private:
    Options opt_{};
};

}
