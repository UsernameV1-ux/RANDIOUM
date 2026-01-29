#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace randio::obs {

enum class Level : std::uint8_t {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
};

struct LoggerOptions final {
    std::filesystem::path path{};
};

class JsonlLogger final {
public:
    explicit JsonlLogger(LoggerOptions opt);

    [[nodiscard]] bool open();

    void log(Level lvl,
             std::string_view component,
             std::string_view msg,
             std::uint64_t tick,
             std::uint64_t height,
             std::vector<std::pair<std::string_view, std::string_view>> fields = {});

    [[nodiscard]] std::uint64_t seq() const;

private:
    LoggerOptions opt_{};
    std::uint64_t seq_{0};

    std::optional<std::string> escape_(std::string_view s) const;
    [[nodiscard]] bool append_line_(std::string_view line);
};

struct Metrics final {
    std::uint64_t ticks{0};
    std::uint64_t uptime_ticks{0};
    std::uint64_t blocks_produced{0};
    std::uint64_t proposals{0};
    std::uint64_t votes{0};
    std::uint64_t slashes{0};
    std::uint64_t rewards_minted{0};
    std::uint64_t tx_applied{0};
    std::uint64_t tx_aborted{0};

    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] bool write_json_file(const std::filesystem::path& p) const;
};

}
