#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "rand/audit/trace.hpp"
#include "rand/exec_engine.hpp"
#include "rand/tx.hpp"

namespace randio::audit {

struct BuildOptions final {
    std::size_t max_keys_per_category{200};
    bool include_changed_keys{true};
};

[[nodiscard]] BlockTrace from_execution(std::uint64_t height,
                                       const crypto::Hash256& prev_hash,
                                       const crypto::Hash256& block_hash,
                                       std::uint16_t protocol_version,
                                       const crypto::Hash256& state_root_before,
                                       const crypto::Hash256& state_root_after,
                                       const ExecutionResult& res,
                                       const std::vector<Transaction>& pool_txs,
                                       const BuildOptions& opt);

}
