#pragma once

#include "rand/abi/types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace randio::module104 {

enum class EncodeStatus : std::uint8_t {
    Ok,
    TypeMismatch,
    NotCanonical,
    SizeLimit,
    DepthLimit,
};

enum class DecodeStatus : std::uint8_t {
    Ok,
    TooShort,
    SizeLimit,
    DepthLimit,
    InvalidWord,
    InvalidOffset,
    InvalidLength,
    NotCanonical,
    TypeMismatch,
    InvalidUtf8,
};

struct EncodeOptions final {
    std::size_t max_total_bytes{1024 * 1024};
    std::size_t max_depth{32};
    std::size_t max_array_elems{65536};
};

struct DecodeOptions final {
    std::size_t max_total_bytes{1024 * 1024};
    std::size_t max_depth{32};
    std::size_t max_array_elems{65536};
    bool require_canonical_offsets{true};
};

[[nodiscard]] bool is_dynamic(const AbiType& t);

[[nodiscard]] std::size_t static_size_bytes(const AbiType& t);

[[nodiscard]] EncodeStatus encode_value(const AbiType& t, const AbiValue& v, std::vector<std::uint8_t>& out, const EncodeOptions& opt);

[[nodiscard]] EncodeStatus encode_params(const std::vector<std::shared_ptr<AbiType>>& types,
                                        const std::vector<std::shared_ptr<AbiValue>>& values,
                                        std::vector<std::uint8_t>& out,
                                        const EncodeOptions& opt);

[[nodiscard]] DecodeStatus decode_value(const AbiType& t,
                                       std::span<const std::uint8_t> bytes,
                                       AbiValue& out,
                                       std::size_t& consumed,
                                       const DecodeOptions& opt);

[[nodiscard]] DecodeStatus decode_params(const std::vector<std::shared_ptr<AbiType>>& types,
                                        std::span<const std::uint8_t> bytes,
                                        std::vector<std::shared_ptr<AbiValue>>& out,
                                        std::size_t& consumed,
                                        const DecodeOptions& opt);

[[nodiscard]] std::optional<std::vector<std::uint8_t>> encode_params(const std::vector<std::shared_ptr<AbiType>>& types,
                                                                     const std::vector<std::shared_ptr<AbiValue>>& values,
                                                                     const EncodeOptions& opt);

}
