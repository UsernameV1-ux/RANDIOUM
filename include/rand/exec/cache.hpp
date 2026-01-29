#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "rand/state.hpp"

namespace randio::exec::cache {

struct Options final {
    bool enabled{false};
    std::size_t max_entries{100000};
    std::size_t max_bytes{64ULL * 1024ULL * 1024ULL};
};

class CodeCache final {
public:
    explicit CodeCache(Options opt);
    ~CodeCache();

    CodeCache(CodeCache&&) noexcept;
    CodeCache& operator=(CodeCache&&) noexcept;

    CodeCache(const CodeCache&) = delete;
    CodeCache& operator=(const CodeCache&) = delete;

    [[nodiscard]] bool enabled() const;

    [[nodiscard]] std::optional<std::optional<std::vector<std::uint8_t>>> get_copy(std::string_view contract_hex) const;
    void put(std::string_view contract_hex, std::optional<std::vector<std::uint8_t>> code);
    void invalidate(std::string_view contract_hex);

    void clear();

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::size_t bytes() const;

private:
    struct Impl;
    Impl* impl_{nullptr};
};

class StorageReadCache final {
public:
    explicit StorageReadCache(Options opt);
    ~StorageReadCache();

    StorageReadCache(StorageReadCache&&) noexcept;
    StorageReadCache& operator=(StorageReadCache&&) noexcept;

    StorageReadCache(const StorageReadCache&) = delete;
    StorageReadCache& operator=(const StorageReadCache&) = delete;

    [[nodiscard]] bool enabled() const;

    [[nodiscard]] std::optional<std::optional<std::vector<std::uint8_t>>> get_copy(std::string_view storage_entry) const;
    void put(std::string_view storage_entry, std::optional<std::vector<std::uint8_t>> value);
    void invalidate(std::string_view storage_entry);

    void clear();

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::size_t bytes() const;

private:
    struct Impl;
    Impl* impl_{nullptr};
};

class AccountCache final {
public:
    explicit AccountCache(Options opt);
    ~AccountCache();

    AccountCache(AccountCache&&) noexcept;
    AccountCache& operator=(AccountCache&&) noexcept;

    AccountCache(const AccountCache&) = delete;
    AccountCache& operator=(const AccountCache&) = delete;

    [[nodiscard]] bool enabled() const;

    [[nodiscard]] std::optional<std::optional<Account>> get(std::string_view id) const;
    void put(std::string_view id, std::optional<Account> a);
    void invalidate(std::string_view id);

    void clear();

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::size_t bytes() const;

private:
    struct Impl;
    Impl* impl_{nullptr};
};

struct ExecCache final {
    explicit ExecCache(Options opt);

    Options opt{};
    CodeCache code;
    StorageReadCache storage;
    AccountCache account;

    void clear();
};

}
