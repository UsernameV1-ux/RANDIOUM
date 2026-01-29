#pragma once

#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rand/consensus/checkpoint.hpp"
#include "rand/sha256.hpp"
#include "rand/staking.hpp"
#include "rand/storage.hpp"
#include "rand/validator.hpp"

#include "rand/wrap/asset.hpp"
#include "rand/wrap/registry.hpp"

namespace randio {

namespace exec::cache {
struct ExecCache;
}

struct Account final {
    std::uint64_t nonce{0};
    std::uint64_t balance{0};
};

struct Transfer final {
    std::string from;
    std::string to;
    std::uint64_t amount{0};
    std::uint64_t fee{0};
    std::uint64_t expected_nonce{0};
};

struct StateDelta final {
    std::vector<std::string> prior_index;
    std::vector<std::pair<std::string, std::optional<Account>>> prior_accounts;

    std::vector<std::string> prior_contract_index;
    std::vector<std::string> prior_storage_index;
    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> prior_codes;
    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> prior_storage;

    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> prior_meta;
};

struct FeeMarketParams final {
    std::uint64_t base_fee_min{1};
    std::uint64_t base_fee_max{1000000000ULL};

    std::uint64_t target_gas_per_block{1000000ULL};
    std::uint64_t max_gas_per_block{2000000ULL};

    std::uint64_t base_fee_adjust_rate_ppm{125000ULL};
};

class GlobalState final {
public:
    struct Options final {
        Storage::Options storage{};
        std::size_t max_account_id_bytes{256};
        std::uint64_t max_supply{(std::numeric_limits<std::uint64_t>::max)()};

        bool exec_cache_enabled{false};
        std::size_t exec_cache_max_entries{100000};
        std::size_t exec_cache_max_bytes{64ULL * 1024ULL * 1024ULL};
    };

    explicit GlobalState(std::filesystem::path data_dir, Options opt);
    ~GlobalState();

    GlobalState(const GlobalState&) = delete;
    GlobalState& operator=(const GlobalState&) = delete;

    GlobalState(GlobalState&&) noexcept = default;
    GlobalState& operator=(GlobalState&&) noexcept = default;

    [[nodiscard]] bool open();

    [[nodiscard]] std::optional<Account> get_account(std::string_view id) const;
    [[nodiscard]] crypto::Hash256 state_root() const;

    [[nodiscard]] std::optional<crypto::Hash256> checkpoint_root() const;

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> latest_signed_checkpoint_bytes() const;

    [[nodiscard]] bool load_validator_set(ValidatorStore& out_keys, StakingLedger& out_staking) const;
    [[nodiscard]] bool set_validator_set(const std::vector<std::pair<ValidatorId, crypto::Hash256>>& pubkeys,
                                        const std::vector<std::pair<ValidatorId, std::uint64_t>>& stakes,
                                        StateDelta& out_delta);

    [[nodiscard]] bool accept_signed_checkpoint(const consensus::SignedCheckpoint& cp, StateDelta& out_delta);

    [[nodiscard]] std::optional<std::uint64_t> minted_total() const;
    [[nodiscard]] std::optional<std::uint64_t> burned_total() const;
    [[nodiscard]] std::optional<std::uint64_t> circulating_supply() const;

    [[nodiscard]] std::uint16_t protocol_version() const;
    [[nodiscard]] bool set_protocol_version(std::uint16_t v, StateDelta& out_delta);

    [[nodiscard]] std::optional<std::pair<std::uint16_t, std::uint64_t>> scheduled_upgrade() const;
    [[nodiscard]] bool schedule_upgrade(std::uint16_t v, std::uint64_t activation_height, StateDelta& out_delta);
    [[nodiscard]] bool apply_scheduled_upgrade(std::uint64_t current_height, StateDelta& out_delta);

    [[nodiscard]] bool halted() const;
    [[nodiscard]] bool set_halted(bool halted, StateDelta& out_delta);
    [[nodiscard]] bool burn_fees(std::uint64_t amount);
    [[nodiscard]] bool burn_fees(std::uint64_t amount, StateDelta& out_delta);

    [[nodiscard]] std::uint64_t base_fee_per_gas() const;
    [[nodiscard]] FeeMarketParams fee_market_params() const;
    [[nodiscard]] bool update_base_fee(std::uint64_t gas_used, StateDelta& out_delta);

    [[nodiscard]] std::optional<std::uint64_t> tip_pool_total() const;
    [[nodiscard]] bool collect_tips(std::uint64_t amount, StateDelta& out_delta);
    [[nodiscard]] bool distribute_tip_pool(const StakingLedger& staking,
                                          const ValidatorId& proposer,
                                          const std::vector<ValidatorId>& voters,
                                          StateDelta& out_delta);

    [[nodiscard]] bool init_genesis_supply(std::uint64_t total_supply,
                                          const std::vector<std::pair<std::string, std::uint64_t>>& allocations,
                                          StateDelta& out_delta);

    [[nodiscard]] bool reward_validators(const StakingLedger& staking,
                                        const ValidatorId& proposer,
                                        const std::vector<ValidatorId>& voters,
                                        std::uint64_t total_reward,
                                        StateDelta& out_delta);

    [[nodiscard]] bool slash_and_burn(const ValidatorId& offender, std::uint64_t amount, StateDelta& out_delta);

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_contract_code(std::string_view contract_hex) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_contract_storage(std::string_view contract_hex,
                                                                                const crypto::Hash256& key) const;

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> get_storage_entry(std::string_view storage_entry) const;

    [[nodiscard]] bool bridge_is_seen(const crypto::Hash256& msg_id) const;
    [[nodiscard]] bool bridge_mark_seen(const crypto::Hash256& msg_id, StateDelta& out_delta);

     [[nodiscard]] bool bridge_seen(const crypto::Hash256& msg_id) const;
     [[nodiscard]] bool mark_bridge_seen(const crypto::Hash256& msg_id, StateDelta& out_delta);

    [[nodiscard]] bool wrap_register_asset(const module116::AssetInfo& asset_info, StateDelta& out_delta);
    [[nodiscard]] std::optional<module116::AssetInfo> wrap_get_asset(const module116::WrappedAssetId& id) const;

    [[nodiscard]] std::optional<std::uint64_t> wrap_supply_minted(const module116::WrappedAssetId& id) const;
    [[nodiscard]] std::optional<std::uint64_t> wrap_supply_burned(const module116::WrappedAssetId& id) const;
    [[nodiscard]] std::uint64_t wrap_supply(const module116::WrappedAssetId& id) const;

    [[nodiscard]] std::vector<module116::WrappedAssetId> wrap_registered_assets() const;

    [[nodiscard]] bool apply_changes(const std::vector<std::pair<std::string, std::optional<Account>>>& changes,
                                    StateDelta& out_delta);

    [[nodiscard]] bool apply_batch(const std::vector<std::pair<std::string, std::optional<Account>>>& acct_changes,
                                  const std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& code_changes,
                                  const std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& storage_changes,
                                  StateDelta& out_delta);

    [[nodiscard]] bool upsert_account(std::string_view id, const Account& a, StateDelta& out_delta);
    [[nodiscard]] bool erase_account(std::string_view id, StateDelta& out_delta);
    [[nodiscard]] bool apply_transfer(const Transfer& t, StateDelta& out_delta);

    [[nodiscard]] bool upsert_contract_code(std::string_view contract_hex,
                                           std::span<const std::uint8_t> code_bytes,
                                           StateDelta& out_delta);
    [[nodiscard]] bool erase_contract_code(std::string_view contract_hex, StateDelta& out_delta);

    [[nodiscard]] bool upsert_contract_storage(std::string_view contract_hex,
                                              const crypto::Hash256& key,
                                              std::span<const std::uint8_t> value,
                                              StateDelta& out_delta);
    [[nodiscard]] bool erase_contract_storage(std::string_view contract_hex, const crypto::Hash256& key, StateDelta& out_delta);

    [[nodiscard]] bool create_checkpoint();

    [[nodiscard]] bool revert(const StateDelta& delta);

private:
    struct ExecCacheDeleter final {
        void operator()(exec::cache::ExecCache* p) const noexcept;
    };

    std::filesystem::path data_dir_;
    Options opt_{};
    Storage storage_;

    std::unique_ptr<exec::cache::ExecCache, ExecCacheDeleter> exec_cache_{};

    std::vector<std::string> index_;
    std::vector<std::string> contract_index_;
    std::vector<std::string> storage_index_;

    [[nodiscard]] bool econ_invariants_ok_() const;
    [[nodiscard]] bool econ_invariants_ok_(std::uint64_t minted, std::uint64_t burned) const;

    [[nodiscard]] bool load_index_();
    [[nodiscard]] bool load_contract_index_();
    [[nodiscard]] bool load_storage_index_();
    void persist_index_(Storage::Batch& b, const std::vector<std::string>& idx);
    void persist_contract_index_(Storage::Batch& b, const std::vector<std::string>& idx);
    void persist_storage_index_(Storage::Batch& b, const std::vector<std::string>& idx);

    [[nodiscard]] std::optional<Account> load_account_(std::string_view id) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> load_code_(std::string_view contract_hex) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> load_storage_(std::string_view storage_entry) const;
    void store_account_(Storage::Batch& b, std::string_view id, const Account& a);
    void erase_account_(Storage::Batch& b, std::string_view id);

    void store_code_(Storage::Batch& b, std::string_view contract_hex, std::span<const std::uint8_t> bytes);
    void erase_code_(Storage::Batch& b, std::string_view contract_hex);

    void store_storage_(Storage::Batch& b, std::string_view storage_entry, std::span<const std::uint8_t> bytes);
    void erase_storage_(Storage::Batch& b, std::string_view storage_entry);

    [[nodiscard]] bool ensure_id_ok_(std::string_view id) const;
    [[nodiscard]] bool ensure_contract_hex_ok_(std::string_view contract_hex) const;
    void index_insert_(std::string_view id);

    [[nodiscard]] bool apply_account_change_(std::string_view id, const std::optional<Account>& next, StateDelta& out_delta);

    [[nodiscard]] bool apply_code_change_(std::string_view contract_hex,
                                         const std::optional<std::vector<std::uint8_t>>& next,
                                         StateDelta& out_delta);
    [[nodiscard]] bool apply_storage_change_(std::string_view storage_entry,
                                            const std::optional<std::vector<std::uint8_t>>& next,
                                            StateDelta& out_delta);

    [[nodiscard]] static std::vector<std::uint8_t> serialize_account_(const Account& a);
    [[nodiscard]] static std::optional<Account> deserialize_account_(const std::vector<std::uint8_t>& bytes);

    [[nodiscard]] static std::vector<std::uint8_t> encode_index_(const std::vector<std::string>& idx);
    [[nodiscard]] static std::optional<std::vector<std::string>> decode_index_(const std::vector<std::uint8_t>& bytes);
};

}
