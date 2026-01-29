#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace randio {
class ChainDB;
class GlobalState;
}

namespace randio::cfg {
struct Config;
}

namespace randio::eth {

[[nodiscard]] std::string handle_eth_jsonrpc(const ChainDB& db,
                                            const GlobalState& st,
                                            const cfg::Config& cfg,
                                            std::string_view request_body);

}
