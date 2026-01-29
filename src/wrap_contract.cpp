#include "rand/wrap/contract.hpp"

#include "rand/vm.hpp"

namespace randio::module116 {

crypto::Hash256 wrap116_marker_hash() {
    return crypto::sha256("WRAP116");
}

std::vector<std::uint8_t> wrap116_marker_code() {
    vm::Bytecode bc;
    bc.version = 1;
    bc.code.clear();
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    const auto m = wrap116_marker_hash();
    bc.code.insert(bc.code.end(), m.begin(), m.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));
    return vm::VM::encode_bytecode(bc);
}

bool is_wrap116_contract(const std::vector<std::uint8_t>& code) {
    return code == wrap116_marker_code();
}

crypto::Hash256 wrap116_contract_address(const WrappedAssetId& asset) {
    return crypto::sha256("wrap116:contract:" + crypto::to_hex(asset.id));
}

}
