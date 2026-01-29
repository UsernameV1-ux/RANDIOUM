#include "rand/consensus.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace randio {
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

crypto::Hash256 hcat(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
    std::vector<std::uint8_t> buf;
    buf.reserve(a.size() + b.size());
    buf.insert(buf.end(), a.begin(), a.end());
    buf.insert(buf.end(), b.begin(), b.end());
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

crypto::Hash256 round_hash(const crypto::Hash256& seed, const crypto::Hash256& pubkey, const std::uint64_t round) {
    std::vector<std::uint8_t> buf;
    buf.reserve(seed.size() + pubkey.size() + 8);
    buf.insert(buf.end(), seed.begin(), seed.end());
    buf.insert(buf.end(), pubkey.begin(), pubkey.end());
    append_u64_le(buf, round);
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

}

std::string ConsensusCore::id_key(const crypto::Hash256& h) {
    return crypto::to_hex(h);
}

ConsensusCore::ConsensusCore(Options opt,
                             ValidatorId self_id,
                             ValidatorStore keys,
                             StakingLedger staking,
                             crypto::Hash256 chain_seed)
    : opt_(opt), self_id_(std::move(self_id)), keys_(std::move(keys)), staking_(std::move(staking)), chain_seed_(chain_seed) {
    last_progress_round_ = 0;

    ConsensusBlock genesis;
    genesis.prop.height = 0;
    genesis.prop.round = 0;
    genesis.id = BlockId{};
    blocks_[id_key(genesis.id)] = genesis;

    QuorumCert g;
    g.round = 0;
    g.block = BlockId{};
    high_qc_ = g;
}

std::uint64_t ConsensusCore::quorum_threshold_() const {
    const auto total = staking_.total_bonded();
    if (total == 0) {
        return 0;
    }
    const auto num = opt_.quorum_numerator;
    const auto den = opt_.quorum_denominator;
    const auto q = (total * num) / den;
    return q + 1;
}

ValidatorId ConsensusCore::leader_for_round(const std::uint64_t round) const {
    ValidatorId best;
    std::uint64_t best_metric = 0;
    bool has = false;

    const auto ids = keys_.ids();
    for (const auto& id : ids) {
        if (staking_.is_slashed(id)) {
            continue;
        }
        const auto stake = staking_.bonded_of(id);
        if (stake == 0) {
            continue;
        }

        const auto pk = keys_.pubkey(id);
        if (!pk) {
            continue;
        }
        const auto score = round_hash(chain_seed_, *pk, round);

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

BlockId ConsensusCore::proposal_id_(const Proposal& p) const {
    std::vector<std::uint8_t> buf;
    buf.reserve(8 + 8 + 32 + 32 + p.proposer.size());
    append_u64_le(buf, p.height);
    append_u64_le(buf, p.round);
    buf.insert(buf.end(), p.parent.begin(), p.parent.end());
    buf.insert(buf.end(), p.state_root.begin(), p.state_root.end());
    buf.insert(buf.end(), p.proposer.begin(), p.proposer.end());
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

Proposal ConsensusCore::make_proposal(const std::uint64_t round, const crypto::Hash256& state_root) {
    Proposal p;
    p.round = round;
    p.state_root = state_root;
    p.proposer = self_id_;

    if (high_qc_) {
        p.parent = high_qc_->block;
        p.height = blocks_[id_key(p.parent)].prop.height + 1;
    } else {
        p.parent = BlockId{};
        p.height = 0;
    }

    return p;
}

crypto::Hash256 ConsensusCore::vote_digest_(const Vote& v) const {
    std::vector<std::uint8_t> buf;
    buf.reserve(8 + 32 + v.voter.size());
    append_u64_le(buf, v.round);
    buf.insert(buf.end(), v.block.begin(), v.block.end());
    buf.insert(buf.end(), v.voter.begin(), v.voter.end());
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

std::optional<Vote> ConsensusCore::make_vote(const Proposal& p) {
    if (opt_.is_halted && opt_.is_halted()) {
        return std::nullopt;
    }
    if (staking_.is_slashed(self_id_)) {
        return std::nullopt;
    }
    if (leader_for_round(p.round) != p.proposer) {
        return std::nullopt;
    }

    Vote v;
    v.round = p.round;
    v.block = proposal_id_(p);
    v.voter = self_id_;

    const auto kp = keys_.keypair(self_id_);
    if (!kp) {
        return std::nullopt;
    }

    const auto dig = vote_digest_(v);
    v.signature = kp->sign(std::span<const std::uint8_t>(dig.data(), dig.size()));
    return v;
}

void ConsensusCore::on_proposal(const Proposal& p) {
    if (invalid_) {
        return;
    }
    if (opt_.is_halted && opt_.is_halted()) {
        return;
    }
    if (p.proposer != leader_for_round(p.round)) {
        return;
    }
    if (p.round < last_progress_round_) {
        return;
    }

    if (p.height == 0) {
        if (p.parent != BlockId{}) {
            return;
        }
    } else {
        const auto pit = blocks_.find(id_key(p.parent));
        if (pit == blocks_.end()) {
            return;
        }
        if (p.height != pit->second.prop.height + 1) {
            return;
        }
    }

    const auto bid = proposal_id_(p);

    ConsensusBlock b;
    b.prop = p;
    b.id = bid;

    blocks_[id_key(bid)] = b;

    last_progress_round_ = (std::max)(last_progress_round_, p.round);
}

void ConsensusCore::on_vote(const Vote& v) {
    if (invalid_) {
        return;
    }
    if (opt_.is_halted && opt_.is_halted()) {
        return;
    }
    if (staking_.is_slashed(v.voter)) {
        return;
    }

    const auto kp = keys_.keypair(v.voter);
    if (!kp) {
        return;
    }

    const auto dig = vote_digest_(v);
    const auto expect_sig = kp->sign(std::span<const std::uint8_t>(dig.data(), dig.size()));
    if (expect_sig != v.signature) {
        return;
    }

    auto& round_map = votes_by_round_[v.round];
    const auto it = round_map.find(v.voter);
    if (it != round_map.end() && it->second != v.block) {
        const auto sl = staking_.slash_amount(v.voter);
        if (sl && opt_.on_slash) {
            if (!opt_.on_slash(v.voter, *sl)) {
                invalid_ = true;
            }
        }
        return;
    }

    round_map[v.voter] = v.block;
    sigs_by_block_[id_key(v.block)][v.voter] = v.signature;

    try_form_qc_(v.block, v.round);
}

void ConsensusCore::try_form_qc_(const BlockId& bid, const std::uint64_t round) {
    if (opt_.is_halted && opt_.is_halted()) {
        return;
    }
    const auto bkey = id_key(bid);
    auto bit = blocks_.find(bkey);
    if (bit == blocks_.end()) {
        return;
    }

    const auto& sigs = sigs_by_block_[bkey];

    std::uint64_t weight = 0;
    std::vector<ValidatorId> voters;
    voters.reserve(sigs.size());

    for (const auto& [voter, _] : sigs) {
        if (staking_.is_slashed(voter)) {
            continue;
        }
        const auto s = staking_.bonded_of(voter);
        if (s == 0) {
            continue;
        }
        weight += s;
        voters.push_back(voter);
    }

    std::sort(voters.begin(), voters.end());

    const auto threshold = quorum_threshold_();
    if (threshold == 0 || weight < threshold) {
        return;
    }

    QuorumCert qc;
    qc.round = round;
    qc.block = bid;
    qc.voters = std::move(voters);

    bit->second.qc = qc;

    if (!high_qc_ || qc.round > high_qc_->round) {
        high_qc_ = qc;
    }

    last_progress_round_ = (std::max)(last_progress_round_, round);

    try_commit_();
}

void ConsensusCore::try_commit_() {
    if (invalid_) {
        return;
    }
    if (opt_.is_halted && opt_.is_halted()) {
        return;
    }
    if (!high_qc_) {
        return;
    }

    auto it = blocks_.find(id_key(high_qc_->block));
    if (it == blocks_.end()) {
        return;
    }

    const auto& b = it->second;
    if (!b.qc) {
        return;
    }

    const auto parent_it = blocks_.find(id_key(b.prop.parent));
    if (parent_it == blocks_.end() || !parent_it->second.qc) {
        return;
    }

    const auto grand_it = blocks_.find(id_key(parent_it->second.prop.parent));
    if (grand_it == blocks_.end() || !grand_it->second.qc) {
        return;
    }

    committed_ = grand_it->second;

    if (committed_ && committed_->prop.height != last_rewarded_height_) {
        last_rewarded_height_ = committed_->prop.height;
        if (opt_.block_reward != 0 && opt_.on_reward) {
            if (committed_->qc) {
                if (!opt_.on_reward(staking_, committed_->prop.proposer, committed_->qc->voters, opt_.block_reward, committed_->prop.height)) {
                    invalid_ = true;
                }
            }
        }
    }
}

std::optional<QuorumCert> ConsensusCore::high_qc() const {
    return high_qc_;
}

std::optional<ConsensusBlock> ConsensusCore::committed() const {
    return committed_;
}

bool ConsensusCore::partitioned(const std::uint64_t current_round) const {
    if (current_round < last_progress_round_) {
        return false;
    }
    const auto delta = current_round - last_progress_round_;
    return delta >= opt_.partition_round_timeout;
}

bool ConsensusCore::recover_if_partitioned(const std::uint64_t current_round) {
    if (!partitioned(current_round)) {
        return false;
    }

    votes_by_round_.clear();
    sigs_by_block_.clear();
    last_progress_round_ = current_round;
    return true;
}

bool ConsensusCore::is_slashed(const ValidatorId& id) const {
    return staking_.is_slashed(id);
}

bool ConsensusCore::invalid() const {
    return invalid_;
}

}
