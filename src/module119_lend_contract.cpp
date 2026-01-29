#include "rand/module119/lend/contract.hpp"

#include "rand/vm.hpp"

namespace randio::module119::lend {

crypto::Hash256 lend119_marker_hash() {
    return crypto::sha256("LEND119");
}

std::vector<std::uint8_t> lend119_marker_code() {
    vm::Bytecode bc;
    bc.version = 1;
    bc.code.clear();
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    const auto m = lend119_marker_hash();
    bc.code.insert(bc.code.end(), m.begin(), m.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));
    return vm::VM::encode_bytecode(bc);
}

bool is_lend119_contract(const std::vector<std::uint8_t>& code) {
    return code == lend119_marker_code();
}

}
