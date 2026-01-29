#include "rand/validate.hpp"

#include "rand/perf.hpp"

namespace randio {

bool validate_tx(const Transaction& tx, const ValidationOptions& opt) {
    perf::add(1);
    if (tx.version > opt.max_tx_version) {
        return false;
    }
    if (tx.payload.size() > opt.max_tx_payload_bytes) {
        return false;
    }

    if (tx.version < 2) {
        if (tx.compute_limit != 0 || tx.compute_price_per_unit != 0) {
            return false;
        }
    } else {
        if ((tx.compute_limit != 0 || tx.compute_price_per_unit != 0) && tx.compute_limit == 0) {
            return false;
        }
    }
    return true;
}

bool validate_block(const Block& b, const ValidationOptions& opt) {
    perf::add(static_cast<std::uint64_t>(b.transactions.size()));
    if (b.transactions.size() > opt.max_block_txs) {
        return false;
    }

    for (const auto& tx : b.transactions) {
        if (!validate_tx(tx, opt)) {
            return false;
        }
    }

    const auto computed = merkle_root(b.transactions);
    if (computed != b.header.merkle_root) {
        return false;
    }

    return true;
}

}
