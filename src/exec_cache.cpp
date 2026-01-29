#include "rand/exec/cache.hpp"

#include "rand/state.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace randio::exec::cache {
namespace {

struct TransparentHash final {
    using is_transparent = void;
    std::size_t operator()(const std::string_view s) const noexcept {
        return std::hash<std::string_view>{}(s);
    }
    std::size_t operator()(const std::string& s) const noexcept {
        return std::hash<std::string_view>{}(std::string_view(s));
    }
};

struct TransparentEq final {
    using is_transparent = void;
    bool operator()(const std::string_view a, const std::string_view b) const noexcept { return a == b; }
    bool operator()(const std::string& a, const std::string& b) const noexcept { return a == b; }
    bool operator()(const std::string& a, const std::string_view b) const noexcept { return std::string_view(a) == b; }
    bool operator()(const std::string_view a, const std::string& b) const noexcept { return a == std::string_view(b); }
};

template <typename V>
struct Entry final {
    std::optional<V> value;
    std::size_t bytes{0};
    std::uint64_t gen{0};
};

struct FifoKey final {
    std::string key;
    std::uint64_t gen{0};
};

[[nodiscard]] std::size_t opt_vec_bytes(const std::optional<std::vector<std::uint8_t>>& v) {
    return v ? v->size() : 0;
}

[[nodiscard]] std::size_t opt_account_bytes(const std::optional<Account>& a) {
    return a ? sizeof(Account) : 0;
}

template <typename V>
class BasicCache final {
public:
    explicit BasicCache(Options opt) : opt_(opt) {}

    [[nodiscard]] bool enabled() const { return opt_.enabled; }

    [[nodiscard]] std::optional<std::optional<V>> get_copy(std::string_view k) const {
        if (!opt_.enabled) {
            return std::nullopt;
        }
        const auto it = map_.find(k);
        if (it == map_.end()) {
            return std::nullopt;
        }
        return it->second.value;
    }

    void put(std::string_view k, std::optional<V> v, const std::size_t vbytes) {
        if (!opt_.enabled) {
            return;
        }

        const std::string ks(k);

        auto it = map_.find(ks);
        if (it != map_.end()) {
            if (it->second.bytes <= bytes_) {
                bytes_ -= it->second.bytes;
            } else {
                bytes_ = 0;
            }
        }

        Entry<V> e;
        e.value = std::move(v);
        e.bytes = ks.size() + vbytes;
        e.gen = next_gen_++;

        bytes_ += e.bytes;
        map_[ks] = std::move(e);
        fifo_.push_back(FifoKey{ks, map_[ks].gen});

        evict_if_needed_();
    }

    void invalidate(std::string_view k) {
        if (!opt_.enabled) {
            return;
        }
        auto it = map_.find(k);
        if (it == map_.end()) {
            return;
        }
        if (it->second.bytes <= bytes_) {
            bytes_ -= it->second.bytes;
        } else {
            bytes_ = 0;
        }
        map_.erase(it);
    }

    void clear() {
        map_.clear();
        fifo_.clear();
        bytes_ = 0;
    }

    [[nodiscard]] std::size_t size() const { return map_.size(); }
    [[nodiscard]] std::size_t bytes() const { return bytes_; }

private:
    Options opt_{};

    std::unordered_map<std::string, Entry<V>, TransparentHash, TransparentEq> map_{};
    std::deque<FifoKey> fifo_{};

    std::size_t bytes_{0};
    std::uint64_t next_gen_{1};

    void evict_if_needed_() {
        const auto max_entries = (opt_.max_entries == 0) ? 1 : opt_.max_entries;
        const auto max_bytes = (opt_.max_bytes == 0) ? 1 : opt_.max_bytes;

        while (!fifo_.empty() && (map_.size() > max_entries || bytes_ > max_bytes)) {
            const auto fk = fifo_.front();
            fifo_.pop_front();

            auto it = map_.find(fk.key);
            if (it == map_.end()) {
                continue;
            }
            if (it->second.gen != fk.gen) {
                continue;
            }
            if (it->second.bytes <= bytes_) {
                bytes_ -= it->second.bytes;
            } else {
                bytes_ = 0;
            }
            map_.erase(it);
        }
    }
};

}

struct CodeCache::Impl final {
    BasicCache<std::vector<std::uint8_t>> c;
};

CodeCache::CodeCache(Options opt) : impl_(new Impl{BasicCache<std::vector<std::uint8_t>>(opt)}) {}
CodeCache::~CodeCache() { delete impl_; }

CodeCache::CodeCache(CodeCache&& o) noexcept : impl_(o.impl_) { o.impl_ = nullptr; }
CodeCache& CodeCache::operator=(CodeCache&& o) noexcept {
    if (this != &o) {
        delete impl_;
        impl_ = o.impl_;
        o.impl_ = nullptr;
    }
    return *this;
}

bool CodeCache::enabled() const { return impl_ && impl_->c.enabled(); }

std::optional<std::optional<std::vector<std::uint8_t>>> CodeCache::get_copy(const std::string_view contract_hex) const {
    if (!impl_) {
        return std::nullopt;
    }
    return impl_->c.get_copy(contract_hex);
}

void CodeCache::put(const std::string_view contract_hex, std::optional<std::vector<std::uint8_t>> code) {
    if (!impl_) {
        return;
    }
    const auto n = opt_vec_bytes(code);
    impl_->c.put(contract_hex, std::move(code), n);
}

void CodeCache::invalidate(const std::string_view contract_hex) {
    if (impl_) {
        impl_->c.invalidate(contract_hex);
    }
}

void CodeCache::clear() {
    if (impl_) {
        impl_->c.clear();
    }
}

std::size_t CodeCache::size() const { return impl_ ? impl_->c.size() : 0; }
std::size_t CodeCache::bytes() const { return impl_ ? impl_->c.bytes() : 0; }

struct StorageReadCache::Impl final {
    BasicCache<std::vector<std::uint8_t>> c;
};

StorageReadCache::StorageReadCache(Options opt) : impl_(new Impl{BasicCache<std::vector<std::uint8_t>>(opt)}) {}
StorageReadCache::~StorageReadCache() { delete impl_; }

StorageReadCache::StorageReadCache(StorageReadCache&& o) noexcept : impl_(o.impl_) { o.impl_ = nullptr; }
StorageReadCache& StorageReadCache::operator=(StorageReadCache&& o) noexcept {
    if (this != &o) {
        delete impl_;
        impl_ = o.impl_;
        o.impl_ = nullptr;
    }
    return *this;
}

bool StorageReadCache::enabled() const { return impl_ && impl_->c.enabled(); }

std::optional<std::optional<std::vector<std::uint8_t>>> StorageReadCache::get_copy(const std::string_view storage_entry) const {
    if (!impl_) {
        return std::nullopt;
    }
    return impl_->c.get_copy(storage_entry);
}

void StorageReadCache::put(const std::string_view storage_entry, std::optional<std::vector<std::uint8_t>> value) {
    if (!impl_) {
        return;
    }
    const auto n = opt_vec_bytes(value);
    impl_->c.put(storage_entry, std::move(value), n);
}

void StorageReadCache::invalidate(const std::string_view storage_entry) {
    if (impl_) {
        impl_->c.invalidate(storage_entry);
    }
}

void StorageReadCache::clear() {
    if (impl_) {
        impl_->c.clear();
    }
}

std::size_t StorageReadCache::size() const { return impl_ ? impl_->c.size() : 0; }
std::size_t StorageReadCache::bytes() const { return impl_ ? impl_->c.bytes() : 0; }

struct AccountCache::Impl final {
    BasicCache<Account> c;
};

AccountCache::AccountCache(Options opt) : impl_(new Impl{BasicCache<Account>(opt)}) {}
AccountCache::~AccountCache() { delete impl_; }

AccountCache::AccountCache(AccountCache&& o) noexcept : impl_(o.impl_) { o.impl_ = nullptr; }
AccountCache& AccountCache::operator=(AccountCache&& o) noexcept {
    if (this != &o) {
        delete impl_;
        impl_ = o.impl_;
        o.impl_ = nullptr;
    }
    return *this;
}

bool AccountCache::enabled() const { return impl_ && impl_->c.enabled(); }

std::optional<std::optional<Account>> AccountCache::get(const std::string_view id) const {
    if (!impl_) {
        return std::nullopt;
    }
    return impl_->c.get_copy(id);
}

void AccountCache::put(const std::string_view id, std::optional<Account> a) {
    if (!impl_) {
        return;
    }
    const auto n = opt_account_bytes(a);
    impl_->c.put(id, std::move(a), n);
}

void AccountCache::invalidate(const std::string_view id) {
    if (impl_) {
        impl_->c.invalidate(id);
    }
}

void AccountCache::clear() {
    if (impl_) {
        impl_->c.clear();
    }
}

std::size_t AccountCache::size() const { return impl_ ? impl_->c.size() : 0; }
std::size_t AccountCache::bytes() const { return impl_ ? impl_->c.bytes() : 0; }

ExecCache::ExecCache(Options o)
    : opt(o), code(o), storage(o), account(o) {}

void ExecCache::clear() {
    code.clear();
    storage.clear();
    account.clear();
}

}
