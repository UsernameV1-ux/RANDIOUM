#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace randio::module104 {

using AbiWord = std::array<std::uint8_t, 32>;
using AbiAddress = std::array<std::uint8_t, 20>;

struct AbiType;

struct UintType final {
    std::uint16_t bits{256};
};

struct IntType final {
    std::uint16_t bits{256};
};

struct BoolType final {};

struct AddressType final {};

struct BytesNType final {
    std::uint16_t n{32};
};

struct BytesType final {};

struct StringType final {};

struct ArrayType final {
    std::shared_ptr<AbiType> elem;
    std::optional<std::size_t> fixed_len;
};

struct TupleType final {
    std::vector<std::shared_ptr<AbiType>> elems;
};

struct AbiType final {
    using Variant = std::variant<UintType, IntType, BoolType, AddressType, BytesNType, BytesType, StringType, ArrayType, TupleType>;
    Variant v;
};

struct AbiValue;

struct UintValue final {
    AbiWord word{};
};

struct IntValue final {
    AbiWord word{};
};

struct BoolValue final {
    bool v{false};
};

struct AddressValue final {
    AbiAddress v{};
};

struct BytesNValue final {
    std::vector<std::uint8_t> bytes;
};

struct BytesValue final {
    std::vector<std::uint8_t> bytes;
};

struct StringValue final {
    std::string s;
};

struct ArrayValue final {
    std::vector<std::shared_ptr<AbiValue>> elems;
};

struct TupleValue final {
    std::vector<std::shared_ptr<AbiValue>> elems;
};

struct AbiValue final {
    using Variant = std::variant<UintValue, IntValue, BoolValue, AddressValue, BytesNValue, BytesValue, StringValue, ArrayValue, TupleValue>;
    Variant v;
};

[[nodiscard]] std::shared_ptr<AbiType> t_uint(std::uint16_t bits);
[[nodiscard]] std::shared_ptr<AbiType> t_int(std::uint16_t bits);
[[nodiscard]] std::shared_ptr<AbiType> t_bool();
[[nodiscard]] std::shared_ptr<AbiType> t_address();
[[nodiscard]] std::shared_ptr<AbiType> t_bytes_n(std::uint16_t n);
[[nodiscard]] std::shared_ptr<AbiType> t_bytes();
[[nodiscard]] std::shared_ptr<AbiType> t_string();
[[nodiscard]] std::shared_ptr<AbiType> t_array(std::shared_ptr<AbiType> elem);
[[nodiscard]] std::shared_ptr<AbiType> t_array(std::shared_ptr<AbiType> elem, std::size_t fixed_len);
[[nodiscard]] std::shared_ptr<AbiType> t_tuple(std::vector<std::shared_ptr<AbiType>> elems);

[[nodiscard]] std::shared_ptr<AbiValue> v_uint(const AbiWord& w);
[[nodiscard]] std::shared_ptr<AbiValue> v_int(const AbiWord& w);
[[nodiscard]] std::shared_ptr<AbiValue> v_bool(bool b);
[[nodiscard]] std::shared_ptr<AbiValue> v_address(const AbiAddress& a);
[[nodiscard]] std::shared_ptr<AbiValue> v_bytes_n(std::vector<std::uint8_t> b);
[[nodiscard]] std::shared_ptr<AbiValue> v_bytes(std::vector<std::uint8_t> b);
[[nodiscard]] std::shared_ptr<AbiValue> v_string(std::string s);
[[nodiscard]] std::shared_ptr<AbiValue> v_array(std::vector<std::shared_ptr<AbiValue>> elems);
[[nodiscard]] std::shared_ptr<AbiValue> v_tuple(std::vector<std::shared_ptr<AbiValue>> elems);

[[nodiscard]] bool abi_equal(const AbiValue& a, const AbiValue& b);

}
