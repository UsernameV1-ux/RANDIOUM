#include "rand/econ_sim.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace randio::econ {
namespace {

std::uint64_t load_u64_le(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<std::uint64_t>(p[i]) << (8u * i));
    }
    return v;
}

void append_u64_le(std::vector<std::uint8_t>& out, const std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8u * i)) & 0xFFu));
    }
}

crypto::Hash256 round_hash(const crypto::Hash256& seed, const crypto::Hash256& pubkey, const std::uint64_t round) {
    std::vector<std::uint8_t> buf;
    buf.reserve(seed.size() + pubkey.size() + 8);
    buf.insert(buf.end(), seed.begin(), seed.end());
    buf.insert(buf.end(), pubkey.begin(), pubkey.end());
    append_u64_le(buf, round);
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

ValidatorId leader_for_round(const ValidatorStore& keys, const StakingLedger& staking, const crypto::Hash256& chain_seed, const std::uint64_t round) {
    ValidatorId best;
    std::uint64_t best_metric = 0;
    bool has = false;

    auto ids = keys.ids();
    std::sort(ids.begin(), ids.end());

    for (const auto& id : ids) {
        if (staking.is_slashed(id)) {
            continue;
        }
        const auto stake = staking.bonded_of(id);
        if (stake == 0) {
            continue;
        }

        const auto pk = keys.pubkey(id);
        if (!pk) {
            continue;
        }
        const auto score = round_hash(chain_seed, *pk, round);
        const auto x = load_u64_le(score.data());
        const auto metric = x / stake;

        if (!has) {
            best = id;
            best_metric = metric;
            has = true;
            continue;
        }

        if (metric < best_metric) {
            best = id;
            best_metric = metric;
            continue;
        }
        if (metric == best_metric && id < best) {
            best = id;
        }
    }

    return best;
}

std::uint64_t quorum_threshold(const StakingLedger& staking, const std::uint64_t num, const std::uint64_t den) {
    const auto total = staking.total_bonded();
    if (total == 0) {
        return 0;
    }
    const auto q = (total * num) / den;
    return q + 1;
}

struct Rng final {
    std::uint64_t state{1};

    [[nodiscard]] std::uint64_t next() {
        state = state * 6364136223846793005ULL + 1ULL;
        return state;
    }

    [[nodiscard]] std::uint64_t uniform_u64(const std::uint64_t lo, const std::uint64_t hi) {
        if (lo >= hi) {
            return lo;
        }
        const auto x = next();
        return lo + (x % (hi - lo + 1));
    }

    [[nodiscard]] std::size_t uniform_index(const std::size_t n) {
        if (n == 0) {
            return 0;
        }
        const auto x = next();
        return static_cast<std::size_t>(x % n);
    }
};

Transaction make_transfer_tx(const std::string& from,
                            const std::string& to,
                            const std::uint64_t amount,
                            const std::uint64_t expected_nonce,
                            const std::uint64_t fee,
                            const std::size_t extra_payload_bytes) {
    Transaction tx;
    tx.version = 1;
    tx.nonce = expected_nonce;
    tx.fee = fee;

    std::vector<std::uint8_t> p;
    p.reserve(1 + 1 + from.size() + 1 + to.size() + 8 + 8 + extra_payload_bytes);
    p.push_back(static_cast<std::uint8_t>(0x01));
    p.push_back(static_cast<std::uint8_t>(from.size()));
    p.insert(p.end(), from.begin(), from.end());
    p.push_back(static_cast<std::uint8_t>(to.size()));
    p.insert(p.end(), to.begin(), to.end());
    append_u64_le(p, amount);
    append_u64_le(p, expected_nonce);
    p.insert(p.end(), extra_payload_bytes, static_cast<std::uint8_t>(0));

    tx.payload = std::move(p);
    return tx;
}

crypto::Hash256 mix_transcript(const crypto::Hash256& cur, const EconomicSimBlockMetrics& m) {
    std::vector<std::uint8_t> buf;
    buf.reserve(32 + 8 * 8 + 1 + m.proposer.size());
    buf.insert(buf.end(), cur.begin(), cur.end());
    append_u64_le(buf, m.height);
    append_u64_le(buf, m.mempool_txs);
    append_u64_le(buf, m.mempool_bytes);
    append_u64_le(buf, m.applied_txs);
    append_u64_le(buf, m.aborted_txs);
    append_u64_le(buf, m.minted_total);
    append_u64_le(buf, m.burned_total);
    append_u64_le(buf, m.circulating_supply);
    buf.push_back(static_cast<std::uint8_t>(m.committed ? 1 : 0));
    buf.insert(buf.end(), m.proposer.begin(), m.proposer.end());
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

struct ScenarioState final {
    bool partitioned{false};
    std::unordered_map<ValidatorId, bool> withhold{};

    std::uint64_t partition_begin{0};
    std::uint64_t partition_end{0};

    std::uint64_t cartel_begin{0};
    std::uint64_t cartel_end{0};

    std::vector<ValidatorId> cartel_ids{};
};

void init_validators(const EconomicSimOptions& opt, ValidatorStore& keys, StakingLedger& staking, std::vector<ValidatorId>& out_ids, const crypto::Hash256& seed) {
    out_ids.clear();
    out_ids.reserve(opt.validator_count);

    for (std::size_t i = 0; i < opt.validator_count; ++i) {
        const auto id = std::string("v") + std::to_string(i);
        out_ids.push_back(id);
        keys.add_keypair(id, ValidatorKeypair::from_secret(crypto::sha256("sec:" + id + ":" + crypto::to_hex(seed))));
        (void)staking.bond(id, 100);
    }
}

void init_attackers(const EconomicSimOptions& opt, std::vector<std::string>& out_ids) {
    out_ids.clear();
    out_ids.reserve(opt.attacker_count);
    for (std::size_t i = 0; i < opt.attacker_count; ++i) {
        out_ids.push_back(std::string("a") + std::to_string(i));
    }
}

bool apply_scheduled_slash(GlobalState& st, StakingLedger& staking, const ValidatorId& offender) {
    const auto sl = staking.slash_amount(offender);
    if (!sl) {
        return true;
    }
    StateDelta d;
    return st.slash_and_burn(offender, *sl, d);
}

bool apply_reward(GlobalState& st,
                  const StakingLedger& staking,
                  const ValidatorId& proposer,
                  const std::vector<ValidatorId>& voters,
                  const std::uint64_t reward) {
    StateDelta d;
    if (!st.reward_validators(staking, proposer, voters, reward, d)) {
        return false;
    }
    StateDelta td;
    return st.distribute_tip_pool(staking, proposer, voters, td);
}

struct CartelDecision final {
    bool committed{false};
    std::vector<ValidatorId> voters;
};

CartelDecision cartel_commit_decision(const StakingLedger& staking,
                                     const std::vector<ValidatorId>& validator_ids,
                                     const std::unordered_map<ValidatorId, bool>& withhold,
                                     const std::uint64_t num,
                                     const std::uint64_t den) {
    CartelDecision d;

    std::uint64_t weight = 0;
    d.voters.clear();
    for (const auto& id : validator_ids) {
        if (staking.is_slashed(id)) {
            continue;
        }
        const auto it = withhold.find(id);
        if (it != withhold.end() && it->second) {
            continue;
        }
        const auto s = staking.bonded_of(id);
        if (s == 0) {
            continue;
        }
        weight += s;
        d.voters.push_back(id);
    }

    const auto th = quorum_threshold(staking, num, den);
    d.committed = (th != 0 && weight >= th);
    std::sort(d.voters.begin(), d.voters.end());
    return d;
}

bool execute_one_block(GlobalState& st,
                       Mempool& mp,
                       const TransactionScheduler& sched,
                       const DeterministicExecutor& ex,
                       const std::uint64_t current_height,
                       const bool committed,
                       std::size_t& out_applied,
                       std::size_t& out_aborted) {
    out_applied = 0;
    out_aborted = 0;

    if (!committed) {
        return true;
    }

    const auto batch = sched.build_batch(mp);
    const auto plan = ExecutionPlanner::plan(batch);
    const auto r = ex.execute(st, plan, current_height);

    out_applied = r.applied.size();
    out_aborted = r.aborted.size();

    for (const auto& id : r.applied) {
        (void)mp.remove(id);
    }
    for (const auto& id : r.aborted) {
        (void)mp.remove(id);
    }

    return true;
}

bool add_transfer(GlobalState& st,
                  Mempool& mp,
                  const std::string& from,
                  const std::string& to,
                  const std::uint64_t fee,
                  const std::uint64_t amount,
                  const std::size_t extra_payload_bytes) {
    const auto a = st.get_account(from);
    if (!a) {
        return false;
    }

    const auto tx = make_transfer_tx(from, to, amount, a->nonce, fee, extra_payload_bytes);
    return mp.add(tx);
}

bool seed_genesis(const EconomicSimOptions& opt, GlobalState& st, const std::vector<ValidatorId>& validators, const std::vector<std::string>& attackers) {
    std::vector<std::pair<std::string, std::uint64_t>> alloc;
    alloc.reserve(validators.size() + attackers.size() + 1);

    const auto n = static_cast<std::uint64_t>(validators.size() + attackers.size() + 1);
    if (n == 0 || opt.max_supply < n) {
        return false;
    }

    std::uint64_t per = opt.max_supply / n;
    if (per == 0) {
        per = 1;
    }
    if (per > 10000) {
        per = 10000;
    }

    std::uint64_t total = 0;
    for (const auto& v : validators) {
        alloc.emplace_back(v, per);
        total += per;
    }
    for (const auto& a : attackers) {
        alloc.emplace_back(a, per);
        total += per;
    }
    alloc.emplace_back("sink", 0);

    StateDelta d;
    return st.init_genesis_supply(total, alloc, d);
}

void scenario_setup(const EconomicSimOptions& opt, const ScenarioKind scenario, ScenarioState& s, const std::vector<ValidatorId>& validators) {
    s.withhold.clear();
    s.cartel_ids.clear();

    if (scenario == ScenarioKind::NetworkPartitionRecovery) {
        s.partition_begin = opt.blocks / 5;
        s.partition_end = (opt.blocks / 5) * 2;
    }

    if (scenario == ScenarioKind::ValidatorCartel) {
        s.cartel_begin = opt.blocks / 5;
        s.cartel_end = (opt.blocks / 5) * 3;
        const std::size_t cartel_n = (validators.size() >= 3) ? (validators.size() / 3) : 1;
        for (std::size_t i = 0; i < cartel_n; ++i) {
            s.cartel_ids.push_back(validators[i]);
        }
    }
}

void scenario_on_block_begin(const EconomicSimOptions& opt,
                            const ScenarioKind scenario,
                            ScenarioState& s,
                            const std::uint64_t height,
                            Rng& rng,
                            GlobalState& st,
                            StakingLedger& staking,
                            Mempool& mp,
                            const std::vector<ValidatorId>& validators,
                            const std::vector<std::string>& attackers) {
    if (scenario == ScenarioKind::NetworkPartitionRecovery) {
        s.partitioned = (height >= s.partition_begin && height < s.partition_end);
    }

    if (scenario == ScenarioKind::ValidatorCartel) {
        const bool cartel_active = (height >= s.cartel_begin && height < s.cartel_end);
        s.withhold.clear();
        if (cartel_active) {
            for (const auto& id : s.cartel_ids) {
                s.withhold[id] = true;
            }
        }
    }

    if (scenario == ScenarioKind::StakeRotationAbuse) {
        if (height % 250 == 0 && height != 0 && validators.size() >= 2) {
            const auto a = validators[0];
            const auto b = validators[1];
            (void)staking.unbond(a, 50, height);
            (void)staking.bond(b, 50);
        }
        if (height % 400 == 0 && height != 0 && validators.size() >= 1) {
            (void)staking.finalize_unbonding(height);
        }
    }

    if (scenario == ScenarioKind::SlashingGriefing) {
        if (height % 100 == 0 && height != 0 && !validators.empty()) {
            const auto idx = rng.uniform_index(validators.size());
            (void)apply_scheduled_slash(st, staking, validators[idx]);
            (void)apply_scheduled_slash(st, staking, validators[idx]);
        }
    }

    if (scenario == ScenarioKind::FeeSpamCongestion) {
        const std::size_t n = opt.spam_txs_per_block;
        for (std::size_t i = 0; i < n; ++i) {
            const auto from = attackers[rng.uniform_index(attackers.size())];
            const auto fee = rng.uniform_u64(opt.min_fee, opt.max_fee);
            const auto extra = (opt.max_payload_bytes == 0) ? 0 : static_cast<std::size_t>(rng.uniform_u64(0, static_cast<std::uint64_t>(opt.max_payload_bytes)));
            (void)add_transfer(st, mp, from, "sink", fee, 1, extra);
        }
        return;
    }

    const std::size_t n = opt.txs_per_block;
    for (std::size_t i = 0; i < n; ++i) {
        const auto from = attackers[rng.uniform_index(attackers.size())];
        const auto to = attackers[rng.uniform_index(attackers.size())];
        const auto fee = rng.uniform_u64(opt.min_fee, opt.max_fee);
        const auto extra = (opt.max_payload_bytes == 0) ? 0 : static_cast<std::size_t>(rng.uniform_u64(0, static_cast<std::uint64_t>(opt.max_payload_bytes)));
        (void)add_transfer(st, mp, from, to, fee, 1, extra);
    }

    if (scenario == ScenarioKind::RewardExtractionFeeManipulation) {
        if (height % 50 == 0 && height != 0) {
            for (std::size_t i = 0; i < opt.spam_txs_per_block / 10; ++i) {
                const auto from = attackers[0];
                const auto fee = opt.max_fee;
                const auto extra = opt.max_payload_bytes;
                (void)add_transfer(st, mp, from, "sink", fee, 1, extra);
            }
        }
    }
}

bool should_commit(const ScenarioKind scenario, const ScenarioState& s, const StakingLedger& staking, const std::vector<ValidatorId>& validator_ids) {
    if (scenario == ScenarioKind::NetworkPartitionRecovery && s.partitioned) {
        return false;
    }

    if (scenario == ScenarioKind::ValidatorCartel) {
        const auto d = cartel_commit_decision(staking, validator_ids, s.withhold, 2, 3);
        return d.committed;
    }

    return true;
}

std::vector<ValidatorId> voters_for_block(const ScenarioKind scenario,
                                         const ScenarioState& s,
                                         const StakingLedger& staking,
                                         const std::vector<ValidatorId>& validator_ids) {
    if (scenario == ScenarioKind::ValidatorCartel) {
        const auto d = cartel_commit_decision(staking, validator_ids, s.withhold, 2, 3);
        return d.voters;
    }

    std::vector<ValidatorId> voters;
    voters.reserve(validator_ids.size());
    for (const auto& id : validator_ids) {
        if (!staking.is_slashed(id) && staking.bonded_of(id) != 0) {
            voters.push_back(id);
        }
    }
    std::sort(voters.begin(), voters.end());
    return voters;
}

std::uint64_t minted_u64(const GlobalState& st) {
    const auto m = st.minted_total();
    return m.value_or(0);
}

std::uint64_t burned_u64(const GlobalState& st) {
    const auto b = st.burned_total();
    return b.value_or(0);
}

std::uint64_t circ_u64(const GlobalState& st) {
    const auto c = st.circulating_supply();
    return c.value_or(0);
}

double max_reward_minus_stake_share(const std::unordered_map<ValidatorId, std::uint64_t>& reward,
                                   const StakingLedger& staking,
                                   const std::vector<ValidatorId>& validators) {
    long double total_reward = 0.0L;
    for (const auto& [_, v] : reward) {
        total_reward += static_cast<long double>(v);
    }

    const auto total_stake = static_cast<long double>(staking.total_bonded());

    if (total_reward == 0.0L || total_stake == 0.0L) {
        return 0.0;
    }

    long double best = 0.0L;

    for (const auto& id : validators) {
        const auto it = reward.find(id);
        const auto r = (it == reward.end()) ? 0.0L : static_cast<long double>(it->second);
        const auto stake = static_cast<long double>(staking.bonded_of(id));
        const auto rs = r / total_reward;
        const auto ss = stake / total_stake;
        const auto diff = rs - ss;
        if (diff > best) {
            best = diff;
        }
    }

    return static_cast<double>(best);
}

}

EconomicSim::EconomicSim(EconomicSimOptions opt) : opt_(opt) {}

EconomicSimResult EconomicSim::run(const std::filesystem::path& data_dir, const ScenarioKind scenario) const {
    EconomicSimResult out;
    out.blocks.clear();
    out.blocks.reserve(static_cast<std::size_t>(opt_.blocks));

    crypto::Hash256 chain_seed = crypto::sha256("econ_sim:" + std::to_string(opt_.seed));

    ValidatorStore keys;
    StakingLedger staking(opt_.staking);

    std::vector<ValidatorId> validator_ids;
    init_validators(opt_, keys, staking, validator_ids, chain_seed);

    std::vector<std::string> attackers;
    init_attackers(opt_, attackers);

    GlobalState::Options gs_opt;
    gs_opt.storage.schema_version = 1;
    gs_opt.max_supply = opt_.max_supply;

    GlobalState st(data_dir, gs_opt);
    if (!st.open()) {
        out.summary.transcript = crypto::sha256("econ_sim_open_failed");
        return out;
    }
    if (!seed_genesis(opt_, st, validator_ids, attackers)) {
        out.summary.transcript = crypto::sha256("econ_sim_genesis_failed");
        return out;
    }

    Mempool mp(opt_.mempool);
    TransactionScheduler sched(opt_.scheduler);
    DeterministicExecutor ex(opt_.executor);

    ScenarioState s;
    scenario_setup(opt_, scenario, s, validator_ids);

    std::unordered_map<ValidatorId, std::uint64_t> reward_accum;
    reward_accum.reserve(validator_ids.size());

    crypto::Hash256 transcript = crypto::sha256("econ_sim_transcript");

    std::uint64_t committed_blocks = 0;

    for (std::uint64_t height = 1; height <= opt_.blocks; ++height) {
        Rng rng;
        rng.state = opt_.seed ^ (height * 0x9e3779b97f4a7c15ULL);

        staking.finalize_unbonding(height);

        scenario_on_block_begin(opt_, scenario, s, height, rng, st, staking, mp, validator_ids, attackers);

        const auto proposer = leader_for_round(keys, staking, chain_seed, height);

        const auto before_m = minted_u64(st);
        const auto before_b = burned_u64(st);

        const bool commit = should_commit(scenario, s, staking, validator_ids);
        if (commit) {
            committed_blocks += 1;
        }

        std::size_t applied = 0;
        std::size_t aborted = 0;
        (void)execute_one_block(st, mp, sched, ex, height, commit, applied, aborted);

        if (scenario == ScenarioKind::SlashingGriefing) {
            if (height % 37 == 0 && !validator_ids.empty()) {
                const auto idx = rng.uniform_index(validator_ids.size());
                (void)apply_scheduled_slash(st, staking, validator_ids[idx]);
            }
        }

        if (scenario == ScenarioKind::StakeRotationAbuse) {
            if (height % 500 == 0 && height != 0 && validator_ids.size() >= 1) {
                (void)apply_scheduled_slash(st, staking, validator_ids[0]);
            }
        }

        std::uint64_t reward_added = 0;
        if (commit && opt_.block_reward != 0 && !proposer.empty()) {
            const auto voters = voters_for_block(scenario, s, staking, validator_ids);

            std::unordered_map<ValidatorId, std::uint64_t> before_bal;
            before_bal.reserve(voters.size() + 1);
            {
                const auto a = st.get_account(proposer);
                if (a) {
                    before_bal[proposer] = a->balance;
                }
                for (const auto& v : voters) {
                    const auto av = st.get_account(v);
                    if (av) {
                        before_bal[v] = av->balance;
                    }
                }
            }

            (void)apply_reward(st, staking, proposer, voters, opt_.block_reward);

            {
                const auto a = st.get_account(proposer);
                const auto after = a ? a->balance : 0;
                const auto before = before_bal[proposer];
                if (after >= before) {
                    const auto d = after - before;
                    reward_accum[proposer] += d;
                    reward_added += d;
                }
                for (const auto& v : voters) {
                    const auto av = st.get_account(v);
                    const auto aft = av ? av->balance : 0;
                    const auto bef = before_bal[v];
                    if (aft >= bef) {
                        const auto d = aft - bef;
                        reward_accum[v] += d;
                        reward_added += d;
                    }
                }
            }
        }

        const auto after_m = minted_u64(st);
        const auto after_b = burned_u64(st);

        EconomicSimBlockMetrics bm;
        bm.height = height;
        bm.committed = commit;
        bm.proposer = proposer;
        bm.mempool_txs = mp.size();
        bm.mempool_bytes = mp.total_bytes();
        bm.applied_txs = applied;
        bm.aborted_txs = aborted;
        bm.minted_total = after_m;
        bm.burned_total = after_b;
        bm.circulating_supply = circ_u64(st);
        bm.minted_delta = (after_m >= before_m) ? (after_m - before_m) : 0;
        bm.burned_delta = (after_b >= before_b) ? (after_b - before_b) : 0;

        transcript = mix_transcript(transcript, bm);

        out.blocks.push_back(std::move(bm));

        const auto m = st.minted_total();
        const auto b = st.burned_total();
        if (m && b) {
            if (*b > *m) {
                break;
            }
            if (*m > opt_.max_supply) {
                break;
            }
        }
    }

    out.summary.transcript = transcript;
    out.summary.blocks = static_cast<std::uint64_t>(out.blocks.size());
    out.summary.committed_blocks = committed_blocks;
    out.summary.minted_total = minted_u64(st);
    out.summary.burned_total = burned_u64(st);
    out.summary.circulating_supply = circ_u64(st);
    out.summary.max_reward_share_minus_stake_share = max_reward_minus_stake_share(reward_accum, staking, validator_ids);

    return out;
}

}
