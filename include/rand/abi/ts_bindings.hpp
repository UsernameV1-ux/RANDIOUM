#pragma once

#include "rand/abi/types.hpp"

#include <memory>
#include <string>
#include <vector>

namespace randio::module105 {

struct TsAbiParam final {
    std::string name;
    std::shared_ptr<module104::AbiType> type;
};

struct TsAbiFunction final {
    std::string name;
    std::vector<TsAbiParam> inputs;
};

[[nodiscard]] std::string generate_ts_bindings(std::string_view contract_name,
                                              const std::vector<TsAbiFunction>& functions);

}
