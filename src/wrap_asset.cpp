#include "rand/wrap/asset.hpp"

namespace randio::module116 {

WrappedAssetId canonical_wrapped_asset_id(const std::string_view chain_name,
                                         const std::string_view symbol,
                                         const std::uint32_t decimals) {
    std::string s;
    s.reserve(64 + chain_name.size() + symbol.size());
    s += "wrap:asset:v1:";
    s += std::string(chain_name);
    s += ":";
    s += std::string(symbol);
    s += ":";
    s += std::to_string(decimals);

    WrappedAssetId out;
    out.id = crypto::sha256(std::string_view(s));
    return out;
}

}
