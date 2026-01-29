#include "rand/obs.hpp"

#include <fstream>
#include <sstream>

namespace randio::obs {
namespace {

[[nodiscard]] const char* level_name(const Level l) {
    switch (l) {
        case Level::Debug:
            return "debug";
        case Level::Info:
            return "info";
        case Level::Warn:
            return "warn";
        case Level::Error:
            return "error";
    }
    return "info";
}

[[nodiscard]] std::string escape_json_string(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (const char c : s) {
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
            continue;
        }
        if (c == '\n') {
            out += "\\n";
            continue;
        }
        if (c == '\r') {
            out += "\\r";
            continue;
        }
        if (c == '\t') {
            out += "\\t";
            continue;
        }
        out.push_back(c);
    }
    return out;
}

[[nodiscard]] bool write_all(const std::filesystem::path& p, std::string_view s) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }
    out.write(s.data(), static_cast<std::streamsize>(s.size()));
    out.flush();
    return out.good();
}

}

JsonlLogger::JsonlLogger(LoggerOptions opt) : opt_(std::move(opt)) {}

bool JsonlLogger::open() {
    if (opt_.path.empty()) {
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(opt_.path.parent_path(), ec);
    return !ec;
}

std::optional<std::string> JsonlLogger::escape_(std::string_view s) const {
    return escape_json_string(s);
}

bool JsonlLogger::append_line_(std::string_view line) {
    std::ofstream out(opt_.path, std::ios::binary | std::ios::app);
    if (!out.is_open()) {
        return false;
    }
    out.write(line.data(), static_cast<std::streamsize>(line.size()));
    out.flush();
    return out.good();
}

void JsonlLogger::log(const Level lvl,
                      const std::string_view component,
                      const std::string_view msg,
                      const std::uint64_t tick,
                      const std::uint64_t height,
                      std::vector<std::pair<std::string_view, std::string_view>> fields) {
    seq_ += 1;

    std::ostringstream ss;
    ss << "{";
    ss << "\"seq\":" << seq_;
    ss << ",\"lvl\":\"" << level_name(lvl) << "\"";
    ss << ",\"component\":\"" << escape_json_string(component) << "\"";
    ss << ",\"msg\":\"" << escape_json_string(msg) << "\"";
    ss << ",\"tick\":" << tick;
    ss << ",\"height\":" << height;

    for (const auto& [k, v] : fields) {
        ss << ",\"" << escape_json_string(k) << "\":\"" << escape_json_string(v) << "\"";
    }

    ss << "}\n";

    (void)append_line_(ss.str());
}

std::uint64_t JsonlLogger::seq() const {
    return seq_;
}

std::string Metrics::to_json() const {
    std::string out;
    out += "{\n";
    out += "  \"ticks\": " + std::to_string(ticks) + ",\n";
    out += "  \"uptime_ticks\": " + std::to_string(uptime_ticks) + ",\n";
    out += "  \"blocks_produced\": " + std::to_string(blocks_produced) + ",\n";
    out += "  \"proposals\": " + std::to_string(proposals) + ",\n";
    out += "  \"votes\": " + std::to_string(votes) + ",\n";
    out += "  \"slashes\": " + std::to_string(slashes) + ",\n";
    out += "  \"rewards_minted\": " + std::to_string(rewards_minted) + ",\n";
    out += "  \"tx_applied\": " + std::to_string(tx_applied) + ",\n";
    out += "  \"tx_aborted\": " + std::to_string(tx_aborted) + "\n";
    out += "}\n";
    return out;
}

bool Metrics::write_json_file(const std::filesystem::path& p) const {
    return write_all(p, to_json());
}

}
