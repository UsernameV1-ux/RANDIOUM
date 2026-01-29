#pragma once

#include <cstdint>

namespace randio::net {

class TokenBucket final {
public:
    struct Options final {
        std::uint64_t capacity{0};
        std::uint64_t refill_per_tick{0};
    };

    explicit TokenBucket(Options opt);

    void tick();
    [[nodiscard]] bool try_consume(std::uint64_t amount);
    [[nodiscard]] std::uint64_t tokens() const;

private:
    Options opt_{};
    std::uint64_t tokens_{0};
};

}
