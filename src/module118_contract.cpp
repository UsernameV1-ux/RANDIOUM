#include "rand/module118/contract.hpp"

#include "rand/vm.hpp"

namespace randio::module118 {

crypto::Hash256 stable118_marker_hash() {
    return crypto::sha256("STABLE118");
}

std::vector<std::uint8_t> stable118_marker_code() {
    vm::Bytecode bc;
    bc.version = 1;
    bc.code.clear();
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    const auto m = stable118_marker_hash();
    bc.code.insert(bc.code.end(), m.begin(), m.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));
    return vm::VM::encode_bytecode(bc);
}

bool is_stable118_contract(const std::vector<std::uint8_t>& code) {
    return code == stable118_marker_code();
}

}
