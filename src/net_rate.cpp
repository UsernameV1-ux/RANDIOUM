#include "rand/net_rate.hpp"

namespace randio::net {

TokenBucket::TokenBucket(Options opt) : opt_(opt), tokens_(opt.capacity) {}

void TokenBucket::tick() {
    const auto next = tokens_ + opt_.refill_per_tick;
    tokens_ = (next < tokens_) ? opt_.capacity : (next > opt_.capacity ? opt_.capacity : next);
}

bool TokenBucket::try_consume(const std::uint64_t amount) {
    if (amount == 0) {
        return true;
    }
    if (tokens_ < amount) {
        return false;
    }
    tokens_ -= amount;
    return true;
}

std::uint64_t TokenBucket::tokens() const {
    return tokens_;
}

}
