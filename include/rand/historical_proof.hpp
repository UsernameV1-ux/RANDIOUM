#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rand/block.hpp"
#include "rand/multiproof.hpp"
#include "rand/proof.hpp"
#include "rand/sha256.hpp"
#include "rand/state.hpp"
#include "rand/tx.hpp"

namespace randio::module88 {

enum class DecodeStatus : std::uint8_t {
    Ok = 0,
    Empty,
    TooShort,
    TooLong,
    BadMagic,
    BadVersion,
    BadKind,
    NonCanonical,
    Invalid,
};

struct DecodeOptions final {
    std::size_t max_total_bytes{4 * 1024 * 1024};
    std::size_t max_id_bytes{256};
    module81::DecodeOptions multiproof_decode{};
    module80::DecodeOptions legacy_proof_decode{};
};

enum class Kind : std::uint8_t {
    Account = 1,
    Tx = 2,
    Receipt = 3,
};

struct HistoricalProof final {
    Kind kind{Kind::Account};

    std::uint64_t proof_height{0};
    BlockHeader header{};
    crypto::Hash256 block_hash{};

    crypto::Hash256 state_root_at_height{};

    std::string account_id;
    Account account{};

    Transaction tx{};
    crypto::Hash256 txid{};
    std::uint64_t tx_index{0};
    bool applied{false};

    module81::MerkleMultiProof multiproof;
};

[[nodiscard]] std::vector<std::uint8_t> encode_historical_proof(const HistoricalProof& p);

[[nodiscard]] DecodeStatus decode_historical_proof(std::span<const std::uint8_t> bytes,
                                                  HistoricalProof& out,
                                                  std::size_t& consumed,
                                                  const DecodeOptions& opt);

[[nodiscard]] std::optional<HistoricalProof> decode_historical_proof(std::span<const std::uint8_t> bytes,
                                                                    const DecodeOptions& opt);

[[nodiscard]] bool verify_historical_proof(const HistoricalProof& p);

[[nodiscard]] std::optional<HistoricalProof> extract_account_proof(const std::filesystem::path& data_dir,
                                                                  std::uint64_t height,
                                                                  std::string_view account_id);

}
