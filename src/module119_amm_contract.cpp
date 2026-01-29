#include "rand/module119/amm/contract.hpp"

#include "rand/vm.hpp"

namespace randio::module119::amm {

crypto::Hash256 amm119_marker_hash() {
    return crypto::sha256("AMM119");
}

std::vector<std::uint8_t> amm119_marker_code() {
    vm::Bytecode bc;
    bc.version = 1;
    bc.code.clear();
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    const auto m = amm119_marker_hash();
    bc.code.insert(bc.code.end(), m.begin(), m.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));
    return vm::VM::encode_bytecode(bc);
}

bool is_amm119_contract(const std::vector<std::uint8_t>& code) {
    return code == amm119_marker_code();
}

}
