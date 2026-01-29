#include "rand/state.hpp"

#include "rand/exec/cache.hpp"

#include "rand/hash256_codec.hpp"
#include "rand/sha256.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace randio {
namespace {

constexpr std::string_view kIndexKey = "state:index";
constexpr std::string_view kContractIndexKey = "state:contracts";
constexpr std::string_view kStorageIndexKey = "state:storage";

constexpr std::string_view kMintedTotalKey = "econ:minted_total";
constexpr std::string_view kBurnedTotalKey = "econ:burned_total";

constexpr std::string_view kBaseFeePerGasKey = "fees:base_fee_per_gas";
constexpr std::string_view kBaseFeeMinKey = "fees:base_fee_min";
constexpr std::string_view kBaseFeeMaxKey = "fees:base_fee_max";
constexpr std::string_view kTargetGasPerBlockKey = "fees:target_gas_per_block";
constexpr std::string_view kMaxGasPerBlockKey = "fees:max_gas_per_block";
constexpr std::string_view kBaseFeeAdjustRatePpmKey = "fees:base_fee_adjust_rate_ppm";
constexpr std::string_view kTipPoolKey = "fees:tip_pool_total";

constexpr std::string_view kProtocolVersionKey = "gov:protocol_version";
constexpr std::string_view kUpgradeVersionKey = "gov:upgrade_version";
constexpr std::string_view kUpgradeHeightKey = "gov:upgrade_height";
constexpr std::string_view kHaltedKey = "gov:halted";

constexpr std::string_view kValidatorIndexKey = "consensus:validators";
constexpr std::string_view kSignedCheckpointKey = "consensus:signed_checkpoint";

constexpr std::string_view kBridgeSeenPrefix = "bridge:seen:";

constexpr std::string_view kWrapAssetPrefix = "wrap:asset:";
constexpr std::string_view kWrapSupplyMintedPrefix = "wrap:supply_minted:";
constexpr std::string_view kWrapSupplyBurnedPrefix = "wrap:supply_burned:";

constexpr std::uint32_t kCheckpointMagic = 0x4B484352u;
constexpr std::uint32_t kCheckpointFormatV1 = 1;

std::string account_key(std::string_view id) {
    return "acct:" + std::string(id);
}

[[nodiscard]] std::string bridge_seen_entry(const crypto::Hash256& msg_id) {
    return std::string(kBridgeSeenPrefix) + crypto::to_hex(msg_id);
}

[[nodiscard]] std::string wrap_asset_entry(const crypto::Hash256& asset_id) {
    return std::string(kWrapAssetPrefix) + crypto::to_hex(asset_id);
}

[[nodiscard]] std::string wrap_supply_minted_entry(const crypto::Hash256& asset_id) {
    return std::string(kWrapSupplyMintedPrefix) + crypto::to_hex(asset_id);
}

[[nodiscard]] std::string wrap_supply_burned_entry(const crypto::Hash256& asset_id) {
    return std::string(kWrapSupplyBurnedPrefix) + crypto::to_hex(asset_id);
}

std::uint64_t clamp_u64(std::uint64_t v, const std::uint64_t lo, const std::uint64_t hi) {
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

std::string validator_pubkey_key(std::string_view id) {
    return "consensus:valpub:" + std::string(id);
}

std::string validator_stake_key(std::string_view id) {
    return "consensus:stake:" + std::string(id);
}

std::vector<std::uint8_t> encode_u64_key(const std::uint64_t v) {
    std::vector<std::uint8_t> out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
    return out;
}

std::string code_key(std::string_view contract_hex) {
    return "code:" + std::string(contract_hex);
}

std::string stor_key(std::string_view storage_entry) {
    return "stor:" + std::string(storage_entry);
}

bool read_exact(std::ifstream& in, std::uint8_t* dst, std::size_t n) {
    in.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(n));
    return in.good();
}

bool write_all(std::ofstream& out, const std::uint8_t* src, std::size_t n) {
    out.write(reinterpret_cast<const char*>(src), static_cast<std::streamsize>(n));
    return out.good();
}

void append_u32_le(std::vector<std::uint8_t>& out, const std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 8u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 16u) & 0xFFu));
    out.push_back(static_cast<std::uint8_t>((v >> 24u) & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

std::uint32_t read_u32_le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8u) |
           (static_cast<std::uint32_t>(p[2]) << 16u) | (static_cast<std::uint32_t>(p[3]) << 24u);
}

std::uint64_t read_u64_le(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
    }
    return v;
}

std::optional<std::uint64_t> read_u64_key(const std::optional<std::vector<std::uint8_t>>& v) {
    if (!v) {
        return std::nullopt;
    }
    if (v->size() != 8) {
        return std::nullopt;
    }
    return read_u64_le(v->data());
}

crypto::Hash256 merkle_root_hashes(std::vector<crypto::Hash256> layer) {
    if (layer.empty()) {
        return crypto::sha256(std::string_view{});
    }

    std::vector<crypto::Hash256> next;
    next.reserve((layer.size() + 1) / 2);
    while (layer.size() > 1) {
        next.clear();
        next.reserve((layer.size() + 1) / 2);

        for (std::size_t i = 0; i < layer.size(); i += 2) {
            const auto& left = layer[i];
            const auto& right = (i + 1 < layer.size()) ? layer[i + 1] : layer[i];

            next.push_back(crypto::sha256_2x32(left, right));
        }

        layer.swap(next);
    }

    return layer[0];
}

std::filesystem::path checkpoint_path(const std::filesystem::path& data_dir) {
    return data_dir / "checkpoint.dat";
}

std::filesystem::path checkpoint_tmp_path(const std::filesystem::path& data_dir) {
    return data_dir / "checkpoint.tmp";
}

}

void GlobalState::ExecCacheDeleter::operator()(exec::cache::ExecCache* p) const noexcept {
    delete p;
}

GlobalState::GlobalState(std::filesystem::path data_dir, Options opt)
    : data_dir_(std::move(data_dir)), opt_(opt), storage_(data_dir_, opt_.storage) {
    if (opt_.exec_cache_enabled) {
        exec::cache::Options copt;
        copt.enabled = true;
        copt.max_entries = opt_.exec_cache_max_entries;
        copt.max_bytes = opt_.exec_cache_max_bytes;
        exec_cache_.reset(new exec::cache::ExecCache(copt));
    }
}

GlobalState::~GlobalState() = default;

bool GlobalState::open() {
    if (!storage_.open()) {
        return false;
    }

    if (exec_cache_) {
        exec_cache_->clear();
    }

    index_.clear();
    if (!load_index_()) {
        return false;
    }

    contract_index_.clear();
    if (!load_contract_index_()) {
        return false;
    }

    storage_index_.clear();
    if (!load_storage_index_()) {
        return false;
    }

    if (!std::is_sorted(index_.begin(), index_.end())) {
        std::sort(index_.begin(), index_.end());
    }
    index_.erase(std::unique(index_.begin(), index_.end()), index_.end());

    if (!std::is_sorted(contract_index_.begin(), contract_index_.end())) {
        std::sort(contract_index_.begin(), contract_index_.end());
    }
    contract_index_.erase(std::unique(contract_index_.begin(), contract_index_.end()), contract_index_.end());

    if (!std::is_sorted(storage_index_.begin(), storage_index_.end())) {
        std::sort(storage_index_.begin(), storage_index_.end());
    }
    storage_index_.erase(std::unique(storage_index_.begin(), storage_index_.end()), storage_index_.end());

    const auto want = checkpoint_root();
    if (want) {
        const auto got = state_root();
        if (got != *want) {
            return false;
        }
    }

    if (!econ_invariants_ok_()) {
        return false;
    }

    return true;
}

bool GlobalState::econ_invariants_ok_() const {
    const auto m = storage_.get(kMintedTotalKey);
    const auto b = storage_.get(kBurnedTotalKey);
    if (!m && !b) {
        return true;
    }
    const auto mv = read_u64_key(m);
    const auto bv = read_u64_key(b);
    if (!mv || !bv) {
        return false;
    }
    return econ_invariants_ok_(*mv, *bv);
}

bool GlobalState::econ_invariants_ok_(const std::uint64_t minted, const std::uint64_t burned) const {
    if (burned > minted) {
        return false;
    }
    if (minted > opt_.max_supply) {
        return false;
    }
    return true;
}

std::optional<crypto::Hash256> GlobalState::checkpoint_root() const {
    const auto p = checkpoint_path(data_dir_);
    if (!std::filesystem::exists(p)) {
        return std::nullopt;
    }

    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        return std::nullopt;
    }

    std::uint8_t hdr[4 + 4 + 32]{};
    if (!read_exact(in, hdr, sizeof(hdr))) {
        return std::nullopt;
    }
    char extra = 0;
    if (in.read(&extra, 1)) {
        return std::nullopt;
    }

    const auto magic = read_u32_le(hdr);
    const auto fmt = read_u32_le(hdr + 4);
    if (magic != kCheckpointMagic || fmt != kCheckpointFormatV1) {
        return std::nullopt;
    }
    crypto::Hash256 want{};
    std::copy(hdr + 8, hdr + 8 + 32, want.begin());
    return want;
}

std::optional<std::uint64_t> GlobalState::minted_total() const {
    return read_u64_key(storage_.get(kMintedTotalKey));
}

std::optional<std::uint64_t> GlobalState::burned_total() const {
    return read_u64_key(storage_.get(kBurnedTotalKey));
}

std::optional<std::uint64_t> GlobalState::tip_pool_total() const {
    return read_u64_key(storage_.get(kTipPoolKey));
}

std::uint64_t GlobalState::base_fee_per_gas() const {
    const auto params = fee_market_params();
    const auto v = read_u64_key(storage_.get(kBaseFeePerGasKey));
    if (!v) {
        return params.base_fee_min;
    }
    return clamp_u64(*v, params.base_fee_min, params.base_fee_max);
}

FeeMarketParams GlobalState::fee_market_params() const {
    FeeMarketParams p;

    if (const auto v = read_u64_key(storage_.get(kBaseFeeMinKey)); v.has_value()) {
        p.base_fee_min = *v;
    }
    if (const auto v = read_u64_key(storage_.get(kBaseFeeMaxKey)); v.has_value()) {
        p.base_fee_max = *v;
    }
    if (const auto v = read_u64_key(storage_.get(kTargetGasPerBlockKey)); v.has_value()) {
        p.target_gas_per_block = *v;
    }
    if (const auto v = read_u64_key(storage_.get(kMaxGasPerBlockKey)); v.has_value()) {
        p.max_gas_per_block = *v;
    }
    if (const auto v = read_u64_key(storage_.get(kBaseFeeAdjustRatePpmKey)); v.has_value()) {
        p.base_fee_adjust_rate_ppm = *v;
    }

    if (p.base_fee_min == 0) {
        p.base_fee_min = FeeMarketParams{}.base_fee_min;
    }
    if (p.base_fee_max < p.base_fee_min) {
        p.base_fee_max = p.base_fee_min;
    }
    if (p.target_gas_per_block == 0) {
        p.target_gas_per_block = 1;
    }
    if (p.max_gas_per_block < p.target_gas_per_block) {
        p.max_gas_per_block = p.target_gas_per_block;
    }
    if (p.base_fee_adjust_rate_ppm > 1000000ULL) {
        p.base_fee_adjust_rate_ppm = 1000000ULL;
    }
    return p;
}

bool GlobalState::update_base_fee(const std::uint64_t gas_used, StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_meta.clear();

    const auto params = fee_market_params();
    const auto cur_raw = storage_.get(kBaseFeePerGasKey);
    const auto cur_fee_opt = read_u64_key(cur_raw);
    const std::uint64_t cur_fee = clamp_u64(cur_fee_opt.value_or(params.base_fee_min), params.base_fee_min, params.base_fee_max);

    const std::uint64_t used = (gas_used > params.max_gas_per_block) ? params.max_gas_per_block : gas_used;
    const std::uint64_t target = (params.target_gas_per_block == 0) ? 1ULL : params.target_gas_per_block;

    const unsigned __int128 num = static_cast<unsigned __int128>(used) * 1000000ULL;
    const std::uint64_t util_ppm = static_cast<std::uint64_t>(num / static_cast<unsigned __int128>(target));

    const std::uint64_t rate = params.base_fee_adjust_rate_ppm;
    const std::uint64_t one = 1000000ULL;

    std::uint64_t mul_ppm = one;
    if (util_ppm > one) {
        const std::uint64_t over = util_ppm - one;
        const unsigned __int128 m = static_cast<unsigned __int128>(rate) * static_cast<unsigned __int128>(over);
        const std::uint64_t inc = static_cast<std::uint64_t>(m / static_cast<unsigned __int128>(one));
        mul_ppm = one + inc;
    } else {
        const std::uint64_t under = one - util_ppm;
        const unsigned __int128 m = static_cast<unsigned __int128>(rate) * static_cast<unsigned __int128>(under);
        const std::uint64_t dec = static_cast<std::uint64_t>(m / static_cast<unsigned __int128>(one));
        mul_ppm = (dec >= one) ? 0ULL : (one - dec);
    }

    const unsigned __int128 next_num = static_cast<unsigned __int128>(cur_fee) * static_cast<unsigned __int128>(mul_ppm);
    std::uint64_t next_fee = static_cast<std::uint64_t>(next_num / static_cast<unsigned __int128>(one));

    if (util_ppm > one && next_fee == cur_fee && cur_fee < params.base_fee_max) {
        next_fee = cur_fee + 1;
    }
    if (util_ppm < one && next_fee == cur_fee && cur_fee > params.base_fee_min) {
        next_fee = cur_fee - 1;
    }

    next_fee = clamp_u64(next_fee, params.base_fee_min, params.base_fee_max);

    out_delta.prior_meta.emplace_back(std::string(kBaseFeePerGasKey), cur_raw);

    auto b = storage_.begin_batch();
    std::vector<std::uint8_t> v;
    v.reserve(8);
    append_u64_le(v, next_fee);
    storage_.put(b, std::string(kBaseFeePerGasKey), std::move(v));
    persist_index_(b, index_);
    if (!storage_.commit(b)) {
        return false;
    }
    return true;
}

bool GlobalState::collect_tips(const std::uint64_t amount, StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_meta.clear();

    if (amount == 0) {
        return true;
    }

    const auto cur_raw = storage_.get(kTipPoolKey);
    const auto cur = read_u64_key(cur_raw).value_or(0);

    const auto next = cur + amount;
    if (next < cur) {
        return false;
    }

    out_delta.prior_meta.emplace_back(std::string(kTipPoolKey), cur_raw);

    auto b = storage_.begin_batch();
    std::vector<std::uint8_t> v;
    v.reserve(8);
    append_u64_le(v, next);
    storage_.put(b, std::string(kTipPoolKey), std::move(v));
    persist_index_(b, index_);
    if (!storage_.commit(b)) {
        return false;
    }
    return true;
}

bool GlobalState::distribute_tip_pool(const StakingLedger& staking,
                                     const ValidatorId& proposer,
                                     const std::vector<ValidatorId>& voters,
                                     StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_accounts.clear();
    out_delta.prior_meta.clear();

    const auto cur_raw = storage_.get(kTipPoolKey);
    const auto cur = read_u64_key(cur_raw).value_or(0);
    if (cur == 0) {
        return true;
    }

    std::vector<ValidatorId> uniq_voters = voters;
    std::sort(uniq_voters.begin(), uniq_voters.end());
    uniq_voters.erase(std::unique(uniq_voters.begin(), uniq_voters.end()), uniq_voters.end());

    struct Part final {
        ValidatorId id;
        std::uint64_t stake{0};
        std::uint64_t reward{0};
    };

    std::vector<Part> parts;
    parts.reserve(1 + uniq_voters.size());

    if (staking.is_slashed(proposer)) {
        return false;
    }
    const auto pstake = staking.bonded_of(proposer);
    if (pstake == 0) {
        return false;
    }
    parts.push_back(Part{proposer, pstake, 0});

    for (const auto& v : uniq_voters) {
        if (v == proposer) {
            continue;
        }
        if (staking.is_slashed(v)) {
            continue;
        }
        const auto s = staking.bonded_of(v);
        if (s == 0) {
            continue;
        }
        parts.push_back(Part{v, s, 0});
    }

    std::uint64_t sum_stake = 0;
    for (const auto& p : parts) {
        const auto next = sum_stake + p.stake;
        if (next < sum_stake) {
            return false;
        }
        sum_stake = next;
    }
    if (sum_stake == 0) {
        return false;
    }

    std::uint64_t distributed = 0;
    for (auto& p : parts) {
        const unsigned __int128 num = static_cast<unsigned __int128>(cur) * static_cast<unsigned __int128>(p.stake);
        const auto q = static_cast<std::uint64_t>(num / static_cast<unsigned __int128>(sum_stake));
        p.reward = q;
        const auto next = distributed + q;
        if (next < distributed) {
            return false;
        }
        distributed = next;
    }
    if (distributed > cur) {
        return false;
    }
    const auto rem = cur - distributed;
    parts[0].reward += rem;

    out_delta.prior_meta.emplace_back(std::string(kTipPoolKey), cur_raw);

    std::vector<std::string> next_index = index_;
    std::sort(next_index.begin(), next_index.end());
    next_index.erase(std::unique(next_index.begin(), next_index.end()), next_index.end());

    auto b = storage_.begin_batch();

    for (const auto& p : parts) {
        if (p.reward == 0) {
            continue;
        }
        const auto prior = load_account_(p.id);
        out_delta.prior_accounts.emplace_back(p.id, prior);
        Account a = prior.value_or(Account{});
        const auto nb = a.balance + p.reward;
        if (nb < a.balance) {
            return false;
        }
        a.balance = nb;
        store_account_(b, p.id, a);

        auto it = std::lower_bound(next_index.begin(), next_index.end(), p.id);
        if (it == next_index.end() || *it != p.id) {
            next_index.insert(it, p.id);
        }
    }

    storage_.put(b, std::string(kTipPoolKey), encode_u64_key(0));
    persist_index_(b, next_index);
    if (!storage_.commit(b)) {
        return false;
    }

    index_ = std::move(next_index);

    if (exec_cache_) {
        for (const auto& p : parts) {
            if (p.reward == 0) {
                continue;
            }
            const auto acc = load_account_(p.id);
            exec_cache_->account.put(p.id, acc);
        }
    }

    return true;
}

std::optional<std::vector<std::uint8_t>> GlobalState::latest_signed_checkpoint_bytes() const {
    return storage_.get(std::string(kSignedCheckpointKey));
}

bool GlobalState::load_validator_set(ValidatorStore& out_keys, StakingLedger& out_staking) const {
    out_keys = ValidatorStore{};
    out_staking = StakingLedger(StakingLedger::Options{});

    const auto raw = storage_.get(std::string(kValidatorIndexKey));
    if (!raw) {
        return false;
    }
    const auto ids = decode_index_(*raw);
    if (!ids) {
        return false;
    }

    for (const auto& id : *ids) {
        const auto pkraw = storage_.get(validator_pubkey_key(id));
        const auto sraw = storage_.get(validator_stake_key(id));
        if (!pkraw || !sraw) {
            return false;
        }
        if (pkraw->size() != 32) {
            return false;
        }
        crypto::Hash256 pk{};
        std::copy(pkraw->begin(), pkraw->end(), pk.begin());

        const auto stake = read_u64_key(sraw);
        if (!stake) {
            return false;
        }

        out_keys.add_pubkey(id, pk);
        if (*stake != 0) {
            if (!out_staking.bond(id, *stake)) {
                return false;
            }
        }
    }

    return true;
}

bool GlobalState::set_validator_set(const std::vector<std::pair<ValidatorId, crypto::Hash256>>& pubkeys,
                                   const std::vector<std::pair<ValidatorId, std::uint64_t>>& stakes,
                                   StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_meta.clear();

    std::vector<std::pair<ValidatorId, crypto::Hash256>> pks = pubkeys;
    std::vector<std::pair<ValidatorId, std::uint64_t>> st = stakes;
    std::sort(pks.begin(), pks.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    std::sort(st.begin(), st.end(), [](const auto& a, const auto& b) { return a.first < b.first; });

    if (pks.size() != st.size()) {
        return false;
    }
    for (std::size_t i = 0; i < pks.size(); ++i) {
        if (pks[i].first.empty() || st[i].first.empty()) {
            return false;
        }
        if (pks[i].first != st[i].first) {
            return false;
        }
        if (i > 0 && pks[i - 1].first == pks[i].first) {
            return false;
        }
    }

    std::vector<std::string> ids;
    ids.reserve(pks.size());
    for (const auto& [id, _] : pks) {
        ids.push_back(id);
    }

    const auto cur_idx = storage_.get(std::string(kValidatorIndexKey));
    out_delta.prior_meta.emplace_back(std::string(kValidatorIndexKey), cur_idx);

    auto b = storage_.begin_batch();
    storage_.put(b, std::string(kValidatorIndexKey), encode_index_(ids));

    for (std::size_t i = 0; i < pks.size(); ++i) {
        const auto& id = pks[i].first;
        const auto& pk = pks[i].second;
        const auto stake = st[i].second;

        const auto pk_key = validator_pubkey_key(id);
        const auto st_key = validator_stake_key(id);

        out_delta.prior_meta.emplace_back(pk_key, storage_.get(pk_key));
        out_delta.prior_meta.emplace_back(st_key, storage_.get(st_key));

        std::vector<std::uint8_t> pkb;
        pkb.reserve(32);
        pkb.insert(pkb.end(), pk.begin(), pk.end());
        storage_.put(b, pk_key, std::move(pkb));
        storage_.put(b, st_key, encode_u64_key(stake));
    }

    persist_index_(b, index_);
    if (!storage_.commit(b)) {
        return false;
    }
    return true;
}

bool GlobalState::accept_signed_checkpoint(const consensus::SignedCheckpoint& cp, StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_meta.clear();

    ValidatorStore keys;
    StakingLedger staking(StakingLedger::Options{});
    if (!load_validator_set(keys, staking)) {
        return false;
    }

    const auto normalized = consensus::normalize_signed_checkpoint(cp);
    if (!normalized) {
        return false;
    }
    if (consensus::verify_signed_checkpoint(*normalized, keys, staking) != consensus::VerifyStatus::Ok) {
        return false;
    }

    const auto cur_raw = storage_.get(std::string(kSignedCheckpointKey));
    std::optional<consensus::SignedCheckpoint> cur;
    if (cur_raw) {
        cur = consensus::decode_signed_checkpoint(std::span<const std::uint8_t>(cur_raw->data(), cur_raw->size()));
    }

    bool take = true;
    if (cur) {
        take = consensus::is_better_checkpoint(*normalized, *cur);
    }
    if (!take) {
        return true;
    }

    out_delta.prior_meta.emplace_back(std::string(kSignedCheckpointKey), cur_raw);

    auto b = storage_.begin_batch();
    const auto enc = consensus::encode_signed_checkpoint(*normalized);
    storage_.put(b, std::string(kSignedCheckpointKey), enc);
    persist_index_(b, index_);
    return storage_.commit(b);
}

std::optional<std::uint64_t> GlobalState::circulating_supply() const {
    const auto m = minted_total();
    const auto b = burned_total();
    if (!m || !b) {
        return std::nullopt;
    }
    if (*b > *m) {
        return std::nullopt;
    }
    return (*m - *b);
}

std::uint16_t GlobalState::protocol_version() const {
    const auto cur = storage_.get(kProtocolVersionKey);
    const auto v = read_u64_key(cur);
    if (!v) {
        return 1;
    }
    if (*v > (std::numeric_limits<std::uint16_t>::max)()) {
        return 1;
    }
    return static_cast<std::uint16_t>(*v);
}

bool GlobalState::set_protocol_version(const std::uint16_t v, StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_meta.clear();

    const auto cur_raw = storage_.get(kProtocolVersionKey);
    const auto cur = read_u64_key(cur_raw);
    const auto base = cur ? *cur : 1ULL;
    if (v < base) {
        return false;
    }

    out_delta.prior_meta.emplace_back(std::string(kProtocolVersionKey), cur_raw);

    auto b = storage_.begin_batch();
    storage_.put(b, std::string(kProtocolVersionKey), encode_u64_key(static_cast<std::uint64_t>(v)));
    persist_index_(b, index_);
    return storage_.commit(b);
}

std::optional<std::pair<std::uint16_t, std::uint64_t>> GlobalState::scheduled_upgrade() const {
    const auto vraw = storage_.get(kUpgradeVersionKey);
    const auto hraw = storage_.get(kUpgradeHeightKey);
    const auto v = read_u64_key(vraw);
    const auto h = read_u64_key(hraw);
    if (!v || !h) {
        return std::nullopt;
    }
    if (*v == 0 || *h == 0) {
        return std::nullopt;
    }
    if (*v > (std::numeric_limits<std::uint16_t>::max)()) {
        return std::nullopt;
    }
    return std::make_pair(static_cast<std::uint16_t>(*v), *h);
}

bool GlobalState::schedule_upgrade(const std::uint16_t v, const std::uint64_t activation_height, StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_meta.clear();

    if (activation_height == 0) {
        return false;
    }

    const auto cur = protocol_version();
    if (v <= cur) {
        return false;
    }

    const auto existing = scheduled_upgrade();
    if (existing) {
        if (existing->first != v || existing->second != activation_height) {
            return false;
        }
        return true;
    }

    const auto vraw = storage_.get(kUpgradeVersionKey);
    const auto hraw = storage_.get(kUpgradeHeightKey);
    out_delta.prior_meta.emplace_back(std::string(kUpgradeVersionKey), vraw);
    out_delta.prior_meta.emplace_back(std::string(kUpgradeHeightKey), hraw);

    auto b = storage_.begin_batch();
    storage_.put(b, std::string(kUpgradeVersionKey), encode_u64_key(static_cast<std::uint64_t>(v)));
    storage_.put(b, std::string(kUpgradeHeightKey), encode_u64_key(activation_height));
    persist_index_(b, index_);
    return storage_.commit(b);
}

bool GlobalState::apply_scheduled_upgrade(const std::uint64_t current_height, StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_meta.clear();

    const auto sch = scheduled_upgrade();
    if (!sch) {
        return true;
    }

    const auto target_v = sch->first;
    const auto target_h = sch->second;

    if (current_height < target_h) {
        return true;
    }
    if (target_v <= protocol_version()) {
        return false;
    }

    const auto cur_vraw = storage_.get(kProtocolVersionKey);
    const auto vraw = storage_.get(kUpgradeVersionKey);
    const auto hraw = storage_.get(kUpgradeHeightKey);
    out_delta.prior_meta.emplace_back(std::string(kProtocolVersionKey), cur_vraw);
    out_delta.prior_meta.emplace_back(std::string(kUpgradeVersionKey), vraw);
    out_delta.prior_meta.emplace_back(std::string(kUpgradeHeightKey), hraw);

    auto b = storage_.begin_batch();
    storage_.put(b, std::string(kProtocolVersionKey), encode_u64_key(static_cast<std::uint64_t>(target_v)));
    storage_.erase(b, std::string(kUpgradeVersionKey));
    storage_.erase(b, std::string(kUpgradeHeightKey));
    persist_index_(b, index_);
    return storage_.commit(b);
}

bool GlobalState::halted() const {
    const auto cur = storage_.get(kHaltedKey);
    const auto v = read_u64_key(cur);
    return v.has_value() && *v != 0;
}

bool GlobalState::set_halted(const bool halted, StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_meta.clear();

    const auto cur = storage_.get(kHaltedKey);
    out_delta.prior_meta.emplace_back(std::string(kHaltedKey), cur);

    auto b = storage_.begin_batch();
    storage_.put(b, std::string(kHaltedKey), encode_u64_key(halted ? 1ULL : 0ULL));
    persist_index_(b, index_);
    return storage_.commit(b);
}

bool GlobalState::reward_validators(const StakingLedger& staking,
                                   const ValidatorId& proposer,
                                   const std::vector<ValidatorId>& voters,
                                   const std::uint64_t total_reward,
                                   StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_accounts.clear();
    out_delta.prior_meta.clear();

    if (total_reward == 0) {
        return true;
    }

    const auto cur_m = storage_.get(kMintedTotalKey);
    const auto cur_b = storage_.get(kBurnedTotalKey);
    const auto base_m = read_u64_key(cur_m);
    const auto base_b = read_u64_key(cur_b);
    if (!base_m || !base_b) {
        return false;
    }

    const auto next_m = *base_m + total_reward;
    if (next_m < *base_m) {
        return false;
    }
    if (!econ_invariants_ok_(next_m, *base_b)) {
        return false;
    }

    std::vector<ValidatorId> uniq_voters = voters;
    std::sort(uniq_voters.begin(), uniq_voters.end());
    uniq_voters.erase(std::unique(uniq_voters.begin(), uniq_voters.end()), uniq_voters.end());

    struct Part final {
        ValidatorId id;
        std::uint64_t stake{0};
        std::uint64_t reward{0};
    };

    std::vector<Part> parts;
    parts.reserve(1 + uniq_voters.size());

    if (staking.is_slashed(proposer)) {
        return false;
    }
    const auto pstake = staking.bonded_of(proposer);
    if (pstake == 0) {
        return false;
    }
    parts.push_back(Part{proposer, pstake, 0});

    for (const auto& v : uniq_voters) {
        if (v == proposer) {
            continue;
        }
        if (staking.is_slashed(v)) {
            continue;
        }
        const auto s = staking.bonded_of(v);
        if (s == 0) {
            continue;
        }
        parts.push_back(Part{v, s, 0});
    }

    std::uint64_t sum_stake = 0;
    for (const auto& p : parts) {
        const auto next = sum_stake + p.stake;
        if (next < sum_stake) {
            return false;
        }
        sum_stake = next;
    }
    if (sum_stake == 0) {
        return false;
    }

    std::uint64_t distributed = 0;
    for (auto& p : parts) {
        const unsigned __int128 num = static_cast<unsigned __int128>(total_reward) * static_cast<unsigned __int128>(p.stake);
        const auto q = static_cast<std::uint64_t>(num / static_cast<unsigned __int128>(sum_stake));
        p.reward = q;
        const auto next = distributed + q;
        if (next < distributed) {
            return false;
        }
        distributed = next;
    }
    if (distributed > total_reward) {
        return false;
    }
    const auto rem = total_reward - distributed;
    parts[0].reward += rem;

    auto b = storage_.begin_batch();

    out_delta.prior_meta.emplace_back(std::string(kMintedTotalKey), cur_m);

    std::vector<std::uint8_t> mv;
    mv.reserve(8);
    append_u64_le(mv, next_m);
    storage_.put(b, std::string(kMintedTotalKey), std::move(mv));

    std::vector<std::string> next_index = index_;
    std::sort(next_index.begin(), next_index.end());
    next_index.erase(std::unique(next_index.begin(), next_index.end()), next_index.end());

    for (const auto& p : parts) {
        if (p.reward == 0) {
            continue;
        }
        const auto prior = load_account_(p.id);
        out_delta.prior_accounts.emplace_back(p.id, prior);
        Account a = prior.value_or(Account{});
        const auto nb = a.balance + p.reward;
        if (nb < a.balance) {
            return false;
        }
        a.balance = nb;
        store_account_(b, p.id, a);

        auto it = std::lower_bound(next_index.begin(), next_index.end(), p.id);
        if (it == next_index.end() || *it != p.id) {
            next_index.insert(it, p.id);
        }
    }

    persist_index_(b, next_index);
    if (!storage_.commit(b)) {
        return false;
    }

    index_ = std::move(next_index);

    if (exec_cache_) {
        for (const auto& p : parts) {
            if (p.reward == 0) {
                continue;
            }
            const auto cur = load_account_(p.id);
            exec_cache_->account.put(p.id, cur);
        }
    }
    return true;
}

bool GlobalState::slash_and_burn(const ValidatorId& offender, const std::uint64_t amount, StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_accounts.clear();
    out_delta.prior_meta.clear();

    if (!ensure_id_ok_(offender)) {
        return false;
    }
    if (amount == 0) {
        return true;
    }

    const auto cur_m = storage_.get(kMintedTotalKey);
    const auto cur_b = storage_.get(kBurnedTotalKey);
    const auto base_m = read_u64_key(cur_m);
    const auto base_b = read_u64_key(cur_b);
    if (!base_m || !base_b) {
        return false;
    }

    const auto prior_acc = load_account_(offender);
    if (!prior_acc) {
        return false;
    }
    if (prior_acc->balance < amount) {
        return false;
    }

    const auto next_b = *base_b + amount;
    if (next_b < *base_b) {
        return false;
    }
    if (!econ_invariants_ok_(*base_m, next_b)) {
        return false;
    }

    out_delta.prior_accounts.emplace_back(offender, prior_acc);
    out_delta.prior_meta.emplace_back(std::string(kBurnedTotalKey), cur_b);

    Account next = *prior_acc;
    next.balance -= amount;

    auto b = storage_.begin_batch();
    store_account_(b, offender, next);

    std::vector<std::uint8_t> bv;
    bv.reserve(8);
    append_u64_le(bv, next_b);
    storage_.put(b, std::string(kBurnedTotalKey), std::move(bv));

    persist_index_(b, index_);
    if (!storage_.commit(b)) {
        return false;
    }
    return true;
}

bool GlobalState::burn_fees(const std::uint64_t amount) {
    StateDelta d;
    return burn_fees(amount, d);
}

bool GlobalState::burn_fees(const std::uint64_t amount, StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;

    if (amount == 0) {
        return true;
    }

    const auto cur_m = storage_.get(kMintedTotalKey);
    const auto cur_b = storage_.get(kBurnedTotalKey);
    const auto base_m = read_u64_key(cur_m);
    const auto base_b = read_u64_key(cur_b);
    if (!base_m || !base_b) {
        return false;
    }

    const auto next_b = *base_b + amount;
    if (next_b < *base_b) {
        return false;
    }
    if (!econ_invariants_ok_(*base_m, next_b)) {
        return false;
    }

    out_delta.prior_meta.clear();
    out_delta.prior_meta.emplace_back(std::string(kBurnedTotalKey), cur_b);

    auto b = storage_.begin_batch();
    std::vector<std::uint8_t> out;
    out.reserve(8);
    append_u64_le(out, next_b);
    storage_.put(b, std::string(kBurnedTotalKey), std::move(out));
    persist_index_(b, index_);
    if (!storage_.commit(b)) {
        return false;
    }
    return true;
}

bool GlobalState::init_genesis_supply(const std::uint64_t total_supply,
                                      const std::vector<std::pair<std::string, std::uint64_t>>& allocations,
                                      StateDelta& out_delta) {
    out_delta = StateDelta{};
    out_delta.prior_index = index_;
    out_delta.prior_accounts.clear();
    out_delta.prior_meta.clear();

    if (!index_.empty()) {
        return false;
    }
    if (storage_.get(kMintedTotalKey).has_value() || storage_.get(kBurnedTotalKey).has_value()) {
        return false;
    }
    if (storage_.get(kBaseFeePerGasKey).has_value() || storage_.get(kBaseFeeMinKey).has_value() || storage_.get(kBaseFeeMaxKey).has_value() ||
        storage_.get(kTargetGasPerBlockKey).has_value() || storage_.get(kMaxGasPerBlockKey).has_value() ||
        storage_.get(kBaseFeeAdjustRatePpmKey).has_value() || storage_.get(kTipPoolKey).has_value()) {
        return false;
    }
    if (storage_.get(kProtocolVersionKey).has_value() || storage_.get(kHaltedKey).has_value() || storage_.get(kUpgradeVersionKey).has_value() ||
        storage_.get(kUpgradeHeightKey).has_value()) {
        return false;
    }
    if (total_supply > opt_.max_supply) {
        return false;
    }

    std::uint64_t sum = 0;
    for (const auto& [id, amt] : allocations) {
        if (!ensure_id_ok_(id)) {
            return false;
        }
        const auto next = sum + amt;
        if (next < sum) {
            return false;
        }
        sum = next;
    }
    if (sum != total_supply) {
        return false;
    }

    std::vector<std::pair<std::string, Account>> to_write;
    to_write.reserve(allocations.size());
    for (const auto& [id, amt] : allocations) {
        if (load_account_(id).has_value()) {
            return false;
        }
        Account a;
        a.nonce = 0;
        a.balance = amt;
        to_write.emplace_back(id, a);
        out_delta.prior_accounts.emplace_back(id, std::nullopt);
    }

    out_delta.prior_meta.emplace_back(std::string(kMintedTotalKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kBurnedTotalKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kBaseFeePerGasKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kBaseFeeMinKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kBaseFeeMaxKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kTargetGasPerBlockKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kMaxGasPerBlockKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kBaseFeeAdjustRatePpmKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kTipPoolKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kProtocolVersionKey), std::nullopt);
    out_delta.prior_meta.emplace_back(std::string(kHaltedKey), std::nullopt);

    auto b = storage_.begin_batch();
    for (const auto& [id, a] : to_write) {
        store_account_(b, id, a);
        index_.push_back(id);
    }
    std::sort(index_.begin(), index_.end());
    index_.erase(std::unique(index_.begin(), index_.end()), index_.end());
    persist_index_(b, index_);

    {
        std::vector<std::uint8_t> mv;
        mv.reserve(8);
        append_u64_le(mv, total_supply);
        storage_.put(b, std::string(kMintedTotalKey), std::move(mv));
    }
    {
        std::vector<std::uint8_t> bv;
        bv.reserve(8);
        append_u64_le(bv, 0);
        storage_.put(b, std::string(kBurnedTotalKey), std::move(bv));
    }

    {
        const FeeMarketParams p;
        storage_.put(b, std::string(kBaseFeeMinKey), encode_u64_key(p.base_fee_min));
        storage_.put(b, std::string(kBaseFeeMaxKey), encode_u64_key(p.base_fee_max));
        storage_.put(b, std::string(kTargetGasPerBlockKey), encode_u64_key(p.target_gas_per_block));
        storage_.put(b, std::string(kMaxGasPerBlockKey), encode_u64_key(p.max_gas_per_block));
        storage_.put(b, std::string(kBaseFeeAdjustRatePpmKey), encode_u64_key(p.base_fee_adjust_rate_ppm));
        storage_.put(b, std::string(kBaseFeePerGasKey), encode_u64_key(p.base_fee_min));
    }

    {
        storage_.put(b, std::string(kTipPoolKey), encode_u64_key(0));
    }

    storage_.put(b, std::string(kProtocolVersionKey), encode_u64_key(1));
    storage_.put(b, std::string(kHaltedKey), encode_u64_key(0));

    if (!storage_.commit(b)) {
        return false;
    }
    return true;
}

bool GlobalState::create_checkpoint() {
    if (!storage_.create_snapshot()) {
        return false;
    }

    const auto root = state_root();

    std::error_code ec;
    std::filesystem::create_directories(data_dir_, ec);
    if (ec) {
        return false;
    }

    const auto tmp = checkpoint_tmp_path(data_dir_);
    const auto final = checkpoint_path(data_dir_);

    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    std::vector<std::uint8_t> buf;
    buf.reserve(4 + 4 + 32);
    append_u32_le(buf, kCheckpointMagic);
    append_u32_le(buf, kCheckpointFormatV1);
    buf.insert(buf.end(), root.begin(), root.end());

    if (!write_all(out, buf.data(), buf.size())) {
        return false;
    }
    out.flush();
    if (!out.good()) {
        return false;
    }
    out.close();

    std::filesystem::remove(final, ec);
    ec.clear();
    std::filesystem::rename(tmp, final, ec);
    if (ec) {
        return false;
    }

    return true;
}

bool GlobalState::apply_changes(const std::vector<std::pair<std::string, std::optional<Account>>>& changes,
                               StateDelta& out_delta) {
    if (changes.empty()) {
        return false;
    }

    std::vector<std::pair<std::string, std::optional<Account>>> ch = changes;
    std::sort(ch.begin(), ch.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    ch.erase(std::unique(ch.begin(), ch.end(), [](const auto& a, const auto& b) { return a.first == b.first; }), ch.end());

    for (const auto& [id, _] : ch) {
        if (!ensure_id_ok_(id)) {
            return false;
        }
    }

    out_delta.prior_index = index_;
    out_delta.prior_accounts.clear();
    out_delta.prior_accounts.reserve(ch.size());
    for (const auto& [id, _] : ch) {
        out_delta.prior_accounts.emplace_back(id, load_account_(id));
    }

    std::vector<std::string> next_index = index_;
    std::sort(next_index.begin(), next_index.end());
    next_index.erase(std::unique(next_index.begin(), next_index.end()), next_index.end());

    for (const auto& [id, next] : ch) {
        auto it = std::lower_bound(next_index.begin(), next_index.end(), id);
        if (next) {
            if (it == next_index.end() || *it != id) {
                next_index.insert(it, id);
            }
        } else {
            if (it != next_index.end() && *it == id) {
                next_index.erase(it);
            }
        }
    }

    auto b = storage_.begin_batch();
    for (const auto& [id, next] : ch) {
        if (next) {
            store_account_(b, id, *next);
        } else {
            erase_account_(b, id);
        }
    }
    persist_index_(b, next_index);

    if (!storage_.commit(b)) {
        return false;
    }

    index_ = std::move(next_index);

    if (exec_cache_) {
        for (const auto& [cid, cnext] : ch) {
            exec_cache_->account.put(cid, cnext);
        }
    }
    return true;
}

bool GlobalState::ensure_id_ok_(const std::string_view id) const {
    if (id.empty()) {
        return false;
    }
    if (id.size() > opt_.max_account_id_bytes) {
        return false;
    }
    return true;
}

bool GlobalState::ensure_contract_hex_ok_(const std::string_view contract_hex) const {
    if (contract_hex.size() != 64) {
        return false;
    }
    for (const char c : contract_hex) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) {
            return false;
        }
    }
    return true;
}

std::optional<Account> GlobalState::load_account_(const std::string_view id) const {
    const auto v = storage_.get(account_key(id));
    if (!v) {
        return std::nullopt;
    }
    return deserialize_account_(*v);
}

std::optional<std::vector<std::uint8_t>> GlobalState::load_code_(const std::string_view contract_hex) const {
    const auto v = storage_.get(code_key(contract_hex));
    if (!v) {
        return std::nullopt;
    }
    return *v;
}

std::optional<std::vector<std::uint8_t>> GlobalState::load_storage_(const std::string_view storage_entry) const {
    const auto v = storage_.get(stor_key(storage_entry));
    if (!v) {
        return std::nullopt;
    }
    return *v;
}

std::optional<Account> GlobalState::get_account(const std::string_view id) const {
    if (!ensure_id_ok_(id)) {
        return std::nullopt;
    }
    if (exec_cache_ && exec_cache_->account.enabled()) {
        const auto cached = exec_cache_->account.get(id);
        if (cached.has_value()) {
            return *cached;
        }
    }

    const auto v = load_account_(id);
    if (exec_cache_) {
        exec_cache_->account.put(id, v);
    }
    return v;
}

std::optional<std::vector<std::uint8_t>> GlobalState::get_contract_code(const std::string_view contract_hex) const {
    if (!ensure_contract_hex_ok_(contract_hex)) {
        return std::nullopt;
    }
    if (exec_cache_ && exec_cache_->code.enabled()) {
        const auto cached = exec_cache_->code.get_copy(contract_hex);
        if (cached.has_value()) {
            return *cached;
        }
    }

    const auto v = load_code_(contract_hex);
    if (exec_cache_) {
        exec_cache_->code.put(contract_hex, v);
    }
    return v;
}

std::optional<std::vector<std::uint8_t>> GlobalState::get_contract_storage(const std::string_view contract_hex,
                                                                           const crypto::Hash256& key) const {
    if (!ensure_contract_hex_ok_(contract_hex)) {
        return std::nullopt;
    }
    const auto entry = std::string(contract_hex) + ":" + crypto::to_hex(key);
    if (exec_cache_ && exec_cache_->storage.enabled()) {
        const auto cached = exec_cache_->storage.get_copy(entry);
        if (cached.has_value()) {
            return *cached;
        }
    }

    const auto v = load_storage_(entry);
    if (exec_cache_) {
        exec_cache_->storage.put(entry, v);
    }
    return v;
}

std::optional<std::vector<std::uint8_t>> GlobalState::get_storage_entry(const std::string_view storage_entry) const {
    if (storage_entry.empty()) {
        return std::nullopt;
    }
    if (exec_cache_ && exec_cache_->storage.enabled()) {
        const auto cached = exec_cache_->storage.get_copy(storage_entry);
        if (cached.has_value()) {
            return *cached;
        }
    }
    const auto v = load_storage_(storage_entry);
    if (exec_cache_) {
        exec_cache_->storage.put(storage_entry, v);
    }
    return v;
}

bool GlobalState::bridge_is_seen(const crypto::Hash256& msg_id) const {
    const auto entry = bridge_seen_entry(msg_id);
    return get_storage_entry(entry).has_value();
}

bool GlobalState::bridge_mark_seen(const crypto::Hash256& msg_id, StateDelta& out_delta) {
    const auto entry = bridge_seen_entry(msg_id);
    if (get_storage_entry(entry).has_value()) {
        return false;
    }
    const std::array<std::uint8_t, 1> one{{1u}};
    return apply_storage_change_(entry, std::vector<std::uint8_t>(one.begin(), one.end()), out_delta);
}

bool GlobalState::bridge_seen(const crypto::Hash256& msg_id) const {
    return bridge_is_seen(msg_id);
}

bool GlobalState::mark_bridge_seen(const crypto::Hash256& msg_id, StateDelta& out_delta) {
    return bridge_mark_seen(msg_id, out_delta);
}

bool GlobalState::wrap_register_asset(const module116::AssetInfo& asset_info, StateDelta& out_delta) {
    const auto wid = module116::canonical_wrapped_asset_id(asset_info.origin_chain, asset_info.symbol, asset_info.decimals);

    const auto akey = wrap_asset_entry(wid.id);
    const auto cur = get_storage_entry(akey);
    const auto next_val = module116::encode_asset_info(asset_info);

    if (cur) {
        if (*cur != next_val) {
            return false;
        }
        out_delta = StateDelta{};
        return true;
    }

    std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>> storage_changes;
    storage_changes.emplace_back(akey, next_val);
    storage_changes.emplace_back(wrap_supply_minted_entry(wid.id), encode_u64_key(0));
    storage_changes.emplace_back(wrap_supply_burned_entry(wid.id), encode_u64_key(0));
    return apply_batch({}, {}, storage_changes, out_delta);
}

std::optional<module116::AssetInfo> GlobalState::wrap_get_asset(const module116::WrappedAssetId& id) const {
    const auto v = get_storage_entry(wrap_asset_entry(id.id));
    if (!v) {
        return std::nullopt;
    }
    return module116::decode_asset_info(std::span<const std::uint8_t>(v->data(), v->size()));
}

std::optional<std::uint64_t> GlobalState::wrap_supply_minted(const module116::WrappedAssetId& id) const {
    return read_u64_key(get_storage_entry(wrap_supply_minted_entry(id.id)));
}

std::optional<std::uint64_t> GlobalState::wrap_supply_burned(const module116::WrappedAssetId& id) const {
    return read_u64_key(get_storage_entry(wrap_supply_burned_entry(id.id)));
}

std::uint64_t GlobalState::wrap_supply(const module116::WrappedAssetId& id) const {
    const auto m = wrap_supply_minted(id).value_or(0);
    const auto b = wrap_supply_burned(id).value_or(0);
    if (b > m) {
        return 0;
    }
    return m - b;
}

std::vector<module116::WrappedAssetId> GlobalState::wrap_registered_assets() const {
    std::vector<module116::WrappedAssetId> out;
    out.reserve(16);

    for (const auto& se : storage_index_) {
        if (se.size() != kWrapAssetPrefix.size() + 64) {
            continue;
        }
        if (se.substr(0, kWrapAssetPrefix.size()) != kWrapAssetPrefix) {
            continue;
        }
        const auto hex = std::string_view(se).substr(kWrapAssetPrefix.size());
        const auto h = module72::from_hex(hex);
        if (!h) {
            continue;
        }
        module116::WrappedAssetId id;
        id.id = *h;
        out.push_back(id);
    }

    std::sort(out.begin(), out.end(), [](const module116::WrappedAssetId& a, const module116::WrappedAssetId& b) { return a.id < b.id; });
    out.erase(std::unique(out.begin(), out.end(), [](const module116::WrappedAssetId& a, const module116::WrappedAssetId& b) { return a.id == b.id; }), out.end());
    return out;
}

void GlobalState::index_insert_(const std::string_view id) {
    const auto it = std::lower_bound(index_.begin(), index_.end(), id, std::less<>{});
    if (it == index_.end() || *it != id) {
        index_.insert(it, std::string(id));
    }
}

bool GlobalState::load_index_() {
    const auto v = storage_.get(kIndexKey);
    if (!v) {
        index_.clear();
        return true;
    }

    const auto decoded = decode_index_(*v);
    if (!decoded) {
        return false;
    }

    index_ = *decoded;
    return true;
}

bool GlobalState::load_contract_index_() {
    const auto v = storage_.get(kContractIndexKey);
    if (!v) {
        contract_index_.clear();
        return true;
    }

    const auto decoded = decode_index_(*v);
    if (!decoded) {
        return false;
    }

    contract_index_ = *decoded;
    return true;
}

bool GlobalState::load_storage_index_() {
    const auto v = storage_.get(kStorageIndexKey);
    if (!v) {
        storage_index_.clear();
        return true;
    }

    const auto decoded = decode_index_(*v);
    if (!decoded) {
        return false;
    }

    storage_index_ = *decoded;
    return true;
}

void GlobalState::persist_index_(Storage::Batch& b, const std::vector<std::string>& idx) {
    storage_.put(b, std::string(kIndexKey), encode_index_(idx));
}

void GlobalState::persist_contract_index_(Storage::Batch& b, const std::vector<std::string>& idx) {
    storage_.put(b, std::string(kContractIndexKey), encode_index_(idx));
}

void GlobalState::persist_storage_index_(Storage::Batch& b, const std::vector<std::string>& idx) {
    storage_.put(b, std::string(kStorageIndexKey), encode_index_(idx));
}

std::vector<std::uint8_t> GlobalState::serialize_account_(const Account& a) {
    std::vector<std::uint8_t> out;
    out.reserve(16);
    append_u64_le(out, a.nonce);
    append_u64_le(out, a.balance);
    return out;
}

std::optional<Account> GlobalState::deserialize_account_(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() != 16) {
        return std::nullopt;
    }

    Account a;
    a.nonce = read_u64_le(bytes.data());
    a.balance = read_u64_le(bytes.data() + 8);
    return a;
}

std::vector<std::uint8_t> GlobalState::encode_index_(const std::vector<std::string>& idx) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + idx.size() * 8);

    append_u32_le(out, static_cast<std::uint32_t>(idx.size()));
    for (const auto& s : idx) {
        append_u32_le(out, static_cast<std::uint32_t>(s.size()));
        out.insert(out.end(), s.begin(), s.end());
    }

    return out;
}

std::optional<std::vector<std::string>> GlobalState::decode_index_(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 4) {
        return std::nullopt;
    }

    std::size_t off = 0;
    const auto count = read_u32_le(bytes.data());
    off += 4;

    std::vector<std::string> idx;
    idx.reserve(count);

    for (std::uint32_t i = 0; i < count; ++i) {
        if (off + 4 > bytes.size()) {
            return std::nullopt;
        }
        const auto len = read_u32_le(bytes.data() + off);
        off += 4;

        if (off + len > bytes.size()) {
            return std::nullopt;
        }

        std::string s(reinterpret_cast<const char*>(bytes.data() + off),
                      reinterpret_cast<const char*>(bytes.data() + off + len));
        off += len;
        idx.push_back(std::move(s));
    }

    if (off != bytes.size()) {
        return std::nullopt;
    }

    return idx;
}

void GlobalState::store_account_(Storage::Batch& b, const std::string_view id, const Account& a) {
    storage_.put(b, account_key(id), serialize_account_(a));
}

void GlobalState::erase_account_(Storage::Batch& b, const std::string_view id) {
    storage_.erase(b, account_key(id));
}

void GlobalState::store_code_(Storage::Batch& b, const std::string_view contract_hex, const std::span<const std::uint8_t> bytes) {
    storage_.put(b, code_key(contract_hex), std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
}

void GlobalState::erase_code_(Storage::Batch& b, const std::string_view contract_hex) {
    storage_.erase(b, code_key(contract_hex));
}

void GlobalState::store_storage_(Storage::Batch& b, const std::string_view storage_entry, const std::span<const std::uint8_t> bytes) {
    storage_.put(b, stor_key(storage_entry), std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
}

void GlobalState::erase_storage_(Storage::Batch& b, const std::string_view storage_entry) {
    storage_.erase(b, stor_key(storage_entry));
}

crypto::Hash256 GlobalState::state_root() const {
    std::vector<std::string> aidx = index_;
    std::sort(aidx.begin(), aidx.end());
    aidx.erase(std::unique(aidx.begin(), aidx.end()), aidx.end());

    std::vector<std::string> cidx = contract_index_;
    std::sort(cidx.begin(), cidx.end());
    cidx.erase(std::unique(cidx.begin(), cidx.end()), cidx.end());

    std::vector<std::string> sidx = storage_index_;
    std::sort(sidx.begin(), sidx.end());
    sidx.erase(std::unique(sidx.begin(), sidx.end()), sidx.end());

    std::vector<crypto::Hash256> leaves;
    leaves.reserve(aidx.size() + cidx.size() + sidx.size());

    for (const auto& id : aidx) {
        const auto a = load_account_(id);
        if (!a) {
            continue;
        }
        std::vector<std::uint8_t> buf;
        buf.reserve(1 + id.size() + 16);
        buf.push_back(0xA1);
        buf.insert(buf.end(), id.begin(), id.end());
        const auto ab = serialize_account_(*a);
        buf.insert(buf.end(), ab.begin(), ab.end());
        leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    }

    auto push_u64_leaf = [&](const std::uint8_t tag, std::string_view key) {
        const auto v = storage_.get(key);
        std::vector<std::uint8_t> buf;
        if (v) {
            buf.reserve(1 + v->size());
            buf.push_back(tag);
            buf.insert(buf.end(), v->begin(), v->end());
        } else {
            buf.reserve(1);
            buf.push_back(tag);
        }
        leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    };

    push_u64_leaf(0xE3, kBaseFeePerGasKey);
    push_u64_leaf(0xE4, kBaseFeeMinKey);
    push_u64_leaf(0xE5, kBaseFeeMaxKey);
    push_u64_leaf(0xE6, kTargetGasPerBlockKey);
    push_u64_leaf(0xE7, kMaxGasPerBlockKey);
    push_u64_leaf(0xE8, kBaseFeeAdjustRatePpmKey);
    push_u64_leaf(0xE9, kTipPoolKey);

    for (const auto& ch : cidx) {
        const auto code = load_code_(ch);
        if (!code) {
            continue;
        }
        const auto chash = crypto::sha256(std::span<const std::uint8_t>(code->data(), code->size()));
        std::vector<std::uint8_t> buf;
        buf.reserve(1 + ch.size() + 32);
        buf.push_back(0xC1);
        buf.insert(buf.end(), ch.begin(), ch.end());
        buf.insert(buf.end(), chash.begin(), chash.end());
        leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    }

    for (const auto& se : sidx) {
        const auto val = load_storage_(se);
        if (!val) {
            continue;
        }
        const auto vhash = crypto::sha256(std::span<const std::uint8_t>(val->data(), val->size()));
        std::vector<std::uint8_t> buf;
        buf.reserve(1 + se.size() + 32);
        buf.push_back(0xD1);
        buf.insert(buf.end(), se.begin(), se.end());
        buf.insert(buf.end(), vhash.begin(), vhash.end());
        leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    }

    {
        const auto v = storage_.get(kMintedTotalKey);
        std::vector<std::uint8_t> buf;
        if (v) {
            buf.reserve(1 + v->size());
            buf.push_back(0xE1);
            buf.insert(buf.end(), v->begin(), v->end());
        } else {
            buf.reserve(1);
            buf.push_back(0xE1);
        }
        leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    }
    {
        const auto v = storage_.get(kBurnedTotalKey);
        std::vector<std::uint8_t> buf;
        if (v) {
            buf.reserve(1 + v->size());
            buf.push_back(0xE2);
            buf.insert(buf.end(), v->begin(), v->end());
        } else {
            buf.reserve(1);
            buf.push_back(0xE2);
        }
        leaves.push_back(crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size())));
    }

    return merkle_root_hashes(std::move(leaves));
}

bool GlobalState::apply_code_change_(const std::string_view contract_hex,
                                    const std::optional<std::vector<std::uint8_t>>& next,
                                    StateDelta& out_delta) {
    if (!ensure_contract_hex_ok_(contract_hex)) {
        return false;
    }

    const auto prior = load_code_(contract_hex);
    out_delta.prior_contract_index = contract_index_;
    out_delta.prior_codes.clear();
    out_delta.prior_codes.emplace_back(std::string(contract_hex), prior);

    std::vector<std::string> next_index = contract_index_;
    auto it = std::lower_bound(next_index.begin(), next_index.end(), contract_hex);
    if (next) {
        if (it == next_index.end() || *it != contract_hex) {
            next_index.insert(it, std::string(contract_hex));
        }
    } else {
        if (it != next_index.end() && *it == contract_hex) {
            next_index.erase(it);
        }
    }

    auto b = storage_.begin_batch();
    if (next) {
        store_code_(b, contract_hex, std::span<const std::uint8_t>(next->data(), next->size()));
    } else {
        erase_code_(b, contract_hex);
    }
    persist_contract_index_(b, next_index);

    if (!storage_.commit(b)) {
        return false;
    }

    contract_index_ = std::move(next_index);

    if (exec_cache_) {
        exec_cache_->code.put(contract_hex, next);
    }
    return true;
}

bool GlobalState::apply_storage_change_(const std::string_view storage_entry,
                                       const std::optional<std::vector<std::uint8_t>>& next,
                                       StateDelta& out_delta) {
    if (storage_entry.size() < 65) {
        return false;
    }

    const auto prior = load_storage_(storage_entry);
    out_delta.prior_storage_index = storage_index_;
    out_delta.prior_storage.clear();
    out_delta.prior_storage.emplace_back(std::string(storage_entry), prior);

    std::vector<std::string> next_index = storage_index_;
    auto it = std::lower_bound(next_index.begin(), next_index.end(), storage_entry);
    if (next) {
        if (it == next_index.end() || *it != storage_entry) {
            next_index.insert(it, std::string(storage_entry));
        }
    } else {
        if (it != next_index.end() && *it == storage_entry) {
            next_index.erase(it);
        }
    }

    auto b = storage_.begin_batch();
    if (next) {
        store_storage_(b, storage_entry, std::span<const std::uint8_t>(next->data(), next->size()));
    } else {
        erase_storage_(b, storage_entry);
    }
    persist_storage_index_(b, next_index);

    if (!storage_.commit(b)) {
        return false;
    }

    storage_index_ = std::move(next_index);

    if (exec_cache_) {
        exec_cache_->storage.put(storage_entry, next);
    }
    return true;
}

bool GlobalState::upsert_contract_code(const std::string_view contract_hex,
                                      const std::span<const std::uint8_t> code_bytes,
                                      StateDelta& out_delta) {
    return apply_code_change_(
        contract_hex,
        std::optional<std::vector<std::uint8_t>>{std::vector<std::uint8_t>(code_bytes.begin(), code_bytes.end())},
        out_delta);
}

bool GlobalState::erase_contract_code(const std::string_view contract_hex, StateDelta& out_delta) {
    return apply_code_change_(contract_hex, std::nullopt, out_delta);
}

bool GlobalState::upsert_contract_storage(const std::string_view contract_hex,
                                         const crypto::Hash256& key,
                                         const std::span<const std::uint8_t> value,
                                         StateDelta& out_delta) {
    if (!ensure_contract_hex_ok_(contract_hex)) {
        return false;
    }
    const auto entry = std::string(contract_hex) + ":" + crypto::to_hex(key);
    return apply_storage_change_(
        entry,
        std::optional<std::vector<std::uint8_t>>{std::vector<std::uint8_t>(value.begin(), value.end())},
        out_delta);
}

bool GlobalState::erase_contract_storage(const std::string_view contract_hex, const crypto::Hash256& key, StateDelta& out_delta) {
    if (!ensure_contract_hex_ok_(contract_hex)) {
        return false;
    }
    const auto entry = std::string(contract_hex) + ":" + crypto::to_hex(key);
    return apply_storage_change_(entry, std::nullopt, out_delta);
}

bool GlobalState::apply_batch(const std::vector<std::pair<std::string, std::optional<Account>>>& acct_changes,
                             const std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& code_changes,
                             const std::vector<std::pair<std::string, std::optional<std::vector<std::uint8_t>>>>& storage_changes,
                             StateDelta& out_delta) {
    if (acct_changes.empty() && code_changes.empty() && storage_changes.empty()) {
        return false;
    }

    for (const auto& [id, _] : acct_changes) {
        if (!ensure_id_ok_(id)) {
            return false;
        }
    }
    for (const auto& [ch, _] : code_changes) {
        if (!ensure_contract_hex_ok_(ch)) {
            return false;
        }
    }
    for (const auto& [se, _] : storage_changes) {
        if (se.size() < 65) {
            return false;
        }
    }

    out_delta.prior_index = index_;
    out_delta.prior_accounts.clear();
    out_delta.prior_contract_index = contract_index_;
    out_delta.prior_codes.clear();
    out_delta.prior_storage_index = storage_index_;
    out_delta.prior_storage.clear();

    for (const auto& [id, _] : acct_changes) {
        out_delta.prior_accounts.emplace_back(id, load_account_(id));
    }
    for (const auto& [ch, _] : code_changes) {
        out_delta.prior_codes.emplace_back(ch, load_code_(ch));
    }
    for (const auto& [se, _] : storage_changes) {
        out_delta.prior_storage.emplace_back(se, load_storage_(se));
    }

    std::vector<std::string> next_a = index_;
    std::sort(next_a.begin(), next_a.end());
    next_a.erase(std::unique(next_a.begin(), next_a.end()), next_a.end());
    for (const auto& [id, next] : acct_changes) {
        auto it = std::lower_bound(next_a.begin(), next_a.end(), id);
        if (next) {
            if (it == next_a.end() || *it != id) {
                next_a.insert(it, id);
            }
        } else {
            if (it != next_a.end() && *it == id) {
                next_a.erase(it);
            }
        }
    }

    std::vector<std::string> next_c = contract_index_;
    std::sort(next_c.begin(), next_c.end());
    next_c.erase(std::unique(next_c.begin(), next_c.end()), next_c.end());
    for (const auto& [id, next] : code_changes) {
        auto it = std::lower_bound(next_c.begin(), next_c.end(), id);
        if (next) {
            if (it == next_c.end() || *it != id) {
                next_c.insert(it, id);
            }
        } else {
            if (it != next_c.end() && *it == id) {
                next_c.erase(it);
            }
        }
    }

    std::vector<std::string> next_s = storage_index_;
    std::sort(next_s.begin(), next_s.end());
    next_s.erase(std::unique(next_s.begin(), next_s.end()), next_s.end());
    for (const auto& [id, next] : storage_changes) {
        auto it = std::lower_bound(next_s.begin(), next_s.end(), id);
        if (next) {
            if (it == next_s.end() || *it != id) {
                next_s.insert(it, id);
            }
        } else {
            if (it != next_s.end() && *it == id) {
                next_s.erase(it);
            }
        }
    }

    auto b = storage_.begin_batch();
    for (const auto& [id, next] : acct_changes) {
        if (next) {
            store_account_(b, id, *next);
        } else {
            erase_account_(b, id);
        }
    }
    for (const auto& [id, next] : code_changes) {
        if (next) {
            store_code_(b, id, std::span<const std::uint8_t>(next->data(), next->size()));
        } else {
            erase_code_(b, id);
        }
    }
    for (const auto& [id, next] : storage_changes) {
        if (next) {
            store_storage_(b, id, std::span<const std::uint8_t>(next->data(), next->size()));
        } else {
            erase_storage_(b, id);
        }
    }

    persist_index_(b, next_a);
    persist_contract_index_(b, next_c);
    persist_storage_index_(b, next_s);

    if (!storage_.commit(b)) {
        return false;
    }

    index_ = std::move(next_a);
    contract_index_ = std::move(next_c);
    storage_index_ = std::move(next_s);

    if (exec_cache_) {
        for (const auto& [id, next] : acct_changes) {
            exec_cache_->account.put(id, next);
        }
        for (const auto& [id, next] : code_changes) {
            exec_cache_->code.put(id, next);
        }
        for (const auto& [id, next] : storage_changes) {
            exec_cache_->storage.put(id, next);
        }
    }
    return true;
}

bool GlobalState::apply_account_change_(const std::string_view id, const std::optional<Account>& next, StateDelta& out_delta) {
    if (!ensure_id_ok_(id)) {
        return false;
    }

    const auto prior_acc = load_account_(id);
    out_delta.prior_index = index_;
    out_delta.prior_accounts.clear();
    out_delta.prior_accounts.emplace_back(std::string(id), prior_acc);

    std::vector<std::string> next_index = index_;
    if (next) {
        if (std::find(next_index.begin(), next_index.end(), id) == next_index.end()) {
            next_index.push_back(std::string(id));
        }
    }
    std::sort(next_index.begin(), next_index.end());
    next_index.erase(std::unique(next_index.begin(), next_index.end()), next_index.end());

    auto b = storage_.begin_batch();
    if (next) {
        store_account_(b, id, *next);
    } else {
        erase_account_(b, id);
    }
    persist_index_(b, next_index);

    if (!storage_.commit(b)) {
        return false;
    }

    index_ = std::move(next_index);

    if (exec_cache_) {
        exec_cache_->account.put(id, next);
    }
    return true;
}

bool GlobalState::upsert_account(const std::string_view id, const Account& a, StateDelta& out_delta) {
    return apply_account_change_(id, std::optional<Account>(a), out_delta);
}

bool GlobalState::erase_account(const std::string_view id, StateDelta& out_delta) {
    return apply_account_change_(id, std::nullopt, out_delta);
}

bool GlobalState::apply_transfer(const Transfer& t, StateDelta& out_delta) {
    if (!ensure_id_ok_(t.from) || !ensure_id_ok_(t.to)) {
        return false;
    }
    if (t.amount == 0) {
        return false;
    }
    if (t.from == t.to) {
        return false;
    }

    const auto from_acc_opt = load_account_(t.from);
    if (!from_acc_opt) {
        return false;
    }

    auto from_acc = *from_acc_opt;
    if (from_acc.nonce != t.expected_nonce) {
        return false;
    }

    const std::uint64_t total = t.amount + t.fee;
    if (total < t.amount) {
        return false;
    }
    if (from_acc.balance < total) {
        return false;
    }

    const auto to_acc_opt = load_account_(t.to);
    Account to_acc = to_acc_opt.value_or(Account{});

    from_acc.balance -= total;
    from_acc.nonce += 1;

    const std::uint64_t new_to_bal = to_acc.balance + t.amount;
    if (new_to_bal < to_acc.balance) {
        return false;
    }
    to_acc.balance = new_to_bal;

    std::vector<std::string> next_index = index_;
    if (std::find(next_index.begin(), next_index.end(), t.from) == next_index.end()) {
        next_index.push_back(t.from);
    }
    if (std::find(next_index.begin(), next_index.end(), t.to) == next_index.end()) {
        next_index.push_back(t.to);
    }
    std::sort(next_index.begin(), next_index.end());
    next_index.erase(std::unique(next_index.begin(), next_index.end()), next_index.end());

    out_delta.prior_index = index_;
    out_delta.prior_accounts.clear();
    out_delta.prior_accounts.emplace_back(t.from, from_acc_opt);
    out_delta.prior_accounts.emplace_back(t.to, to_acc_opt);

    auto b = storage_.begin_batch();
    store_account_(b, t.from, from_acc);
    store_account_(b, t.to, to_acc);
    persist_index_(b, next_index);

    if (!storage_.commit(b)) {
        return false;
    }

    index_ = std::move(next_index);
    return true;
}

bool GlobalState::revert(const StateDelta& delta) {
    auto b = storage_.begin_batch();

    persist_index_(b, delta.prior_index);

    if (!delta.prior_contract_index.empty()) {
        persist_contract_index_(b, delta.prior_contract_index);
    }
    if (!delta.prior_storage_index.empty()) {
        persist_storage_index_(b, delta.prior_storage_index);
    }

    for (const auto& [id, prior] : delta.prior_accounts) {
        if (!ensure_id_ok_(id)) {
            return false;
        }
        if (prior) {
            store_account_(b, id, *prior);
        } else {
            erase_account_(b, id);
        }
    }

    for (const auto& [ch, prior] : delta.prior_codes) {
        if (!ensure_contract_hex_ok_(ch)) {
            return false;
        }
        if (prior) {
            store_code_(b, ch, std::span<const std::uint8_t>(prior->data(), prior->size()));
        } else {
            erase_code_(b, ch);
        }
    }

    for (const auto& [se, prior] : delta.prior_storage) {
        if (se.size() < 65) {
            return false;
        }
        if (prior) {
            store_storage_(b, se, std::span<const std::uint8_t>(prior->data(), prior->size()));
        } else {
            erase_storage_(b, se);
        }
    }

    for (const auto& [k, prior] : delta.prior_meta) {
        if (prior) {
            storage_.put(b, k, *prior);
        } else {
            storage_.erase(b, k);
        }
    }

    if (!storage_.commit(b)) {
        return false;
    }

    index_ = delta.prior_index;
    if (!delta.prior_contract_index.empty()) {
        contract_index_ = delta.prior_contract_index;
    }
    if (!delta.prior_storage_index.empty()) {
        storage_index_ = delta.prior_storage_index;
    }

    if (exec_cache_) {
        for (const auto& [id, prior] : delta.prior_accounts) {
            exec_cache_->account.put(id, prior);
        }
        for (const auto& [id, prior] : delta.prior_codes) {
            exec_cache_->code.put(id, prior);
        }
        for (const auto& [id, prior] : delta.prior_storage) {
            exec_cache_->storage.put(id, prior);
        }
    }
    return true;
}

}
