#include "rand/module108.hpp"

#include "rand/vm.hpp"

#include "rand/sha256.hpp"

#include <array>
#include <fstream>
#include <sstream>

namespace randio::module108 {

namespace {

[[nodiscard]] bool write_all(const std::filesystem::path& p, std::string_view s) {
    if (p.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
        if (ec) {
            return false;
        }
    }

    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }
    out.write(s.data(), static_cast<std::streamsize>(s.size()));
    out.flush();
    if (!out.good()) {
        return false;
    }
    out.close();
    return out.good();
}

[[nodiscard]] std::optional<std::string> read_all(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) {
        return std::nullopt;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

[[nodiscard]] std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\\' || c == '"') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else if (c == '\t') {
            out += "\\t";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

[[nodiscard]] std::optional<std::string> json_get_string(std::string_view s, std::string_view key) {
    const auto k = std::string("\"") + std::string(key) + "\"";
    const auto pos = s.find(k);
    if (pos == std::string_view::npos) {
        return std::nullopt;
    }
    const auto colon = s.find(':', pos + k.size());
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    const auto q1 = s.find('"', colon + 1);
    if (q1 == std::string_view::npos) {
        return std::nullopt;
    }
    std::string out;
    std::size_t i = q1 + 1;
    while (i < s.size()) {
        const char c = s[i++];
        if (c == '"') {
            return out;
        }
        if (c == '\\') {
            if (i >= s.size()) {
                return std::nullopt;
            }
            const char e = s[i++];
            if (e == '"' || e == '\\' || e == '/') {
                out.push_back(e);
            } else if (e == 'b') {
                out.push_back('\b');
            } else if (e == 'f') {
                out.push_back('\f');
            } else if (e == 'n') {
                out.push_back('\n');
            } else if (e == 'r') {
                out.push_back('\r');
            } else if (e == 't') {
                out.push_back('\t');
            } else {
                return std::nullopt;
            }
            continue;
        }
        out.push_back(c);
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> bytes_from_hex(std::string_view s) {
    if (s.starts_with("0x") || s.starts_with("0X")) {
        s = s.substr(2);
    }
    if ((s.size() % 2u) != 0u) {
        return std::nullopt;
    }
    const auto nbytes = s.size() / 2u;
    std::vector<std::uint8_t> out;
    out.resize(nbytes);
    auto nibble = [](const char c) -> std::optional<std::uint8_t> {
        if (c >= '0' && c <= '9') {
            return static_cast<std::uint8_t>(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return static_cast<std::uint8_t>(10 + (c - 'a'));
        }
        if (c >= 'A' && c <= 'F') {
            return static_cast<std::uint8_t>(10 + (c - 'A'));
        }
        return std::nullopt;
    };
    for (std::size_t i = 0; i < nbytes; ++i) {
        const auto hi = nibble(s[i * 2]);
        const auto lo = nibble(s[i * 2 + 1]);
        if (!hi || !lo) {
            return std::nullopt;
        }
        out[i] = static_cast<std::uint8_t>((*hi << 4u) | *lo);
    }
    return out;
}

[[nodiscard]] std::string bytes_to_hex(const std::span<const std::uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto b = bytes[i];
        out[i * 2] = kDigits[(b >> 4u) & 0x0Fu];
        out[i * 2 + 1] = kDigits[b & 0x0Fu];
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> deterministic_fallback_bytecode(std::string_view source_text,
                                                                        std::string_view source_path,
                                                                        std::string_view contract_name) {
    const auto h = crypto::sha256(std::string(source_text) + "\n" + std::string(source_path) + "\n" + std::string(contract_name));

    vm::Bytecode bc;
    bc.version = 1;
    bc.code.clear();

    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::PUSH_BYTES32));
    bc.code.insert(bc.code.end(), h.begin(), h.end());
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::SSTORE));
    bc.code.push_back(static_cast<std::uint8_t>(vm::VM::Op::STOP));

    return vm::VM::encode_bytecode(bc);
}

} // namespace

int link_anchor() {
    return 108;
}

std::string encode_artifact_json(const SolidityArtifact& a) {
    std::string out;
    out += "{\n";
    out += "  \"format\": \"" + json_escape(a.format) + "\",\n";
    out += "  \"contract\": \"" + json_escape(a.contract) + "\",\n";
    out += "  \"source\": \"" + json_escape(a.source) + "\",\n";
    out += "  \"compiler\": \"" + json_escape(a.compiler) + "\",\n";
    out += "  \"abi_json\": \"" + json_escape(a.abi_json) + "\",\n";
    out += "  \"bytecode_hex\": \"" + bytes_to_hex(std::span<const std::uint8_t>(a.bytecode.data(), a.bytecode.size())) + "\"\n";
    out += "}\n";
    return out;
}

std::optional<SolidityArtifact> decode_artifact_json(std::string_view json) {
    SolidityArtifact a;
    const auto fmt = json_get_string(json, "format");
    const auto contract = json_get_string(json, "contract");
    const auto source = json_get_string(json, "source");
    const auto compiler = json_get_string(json, "compiler");
    const auto abi = json_get_string(json, "abi_json");
    const auto bytecode_hex = json_get_string(json, "bytecode_hex");

    if (!fmt || !contract || !source || !compiler || !abi || !bytecode_hex) {
        return std::nullopt;
    }

    const auto bc = bytes_from_hex(*bytecode_hex);
    if (!bc) {
        return std::nullopt;
    }
    a.format = *fmt;
    a.contract = *contract;
    a.source = *source;
    a.compiler = *compiler;
    a.abi_json = *abi;
    a.bytecode = *bc;
    return a;
}

bool write_artifact_file(const std::filesystem::path& p, const SolidityArtifact& a) {
    return write_all(p, encode_artifact_json(a));
}

std::optional<SolidityArtifact> read_artifact_file(const std::filesystem::path& p) {
    const auto s = read_all(p);
    if (!s) {
        return std::nullopt;
    }
    return decode_artifact_json(*s);
}

SolidityArtifact compile_solidity_fallback(std::string_view source_text,
                                          std::string_view source_path,
                                          std::string_view contract_name) {
    SolidityArtifact a;
    a.format = "randium.sol.artifact.v1";
    a.contract = std::string(contract_name);
    a.source = std::string(source_path);
    a.compiler = "fallback";
    a.abi_json = "[]";
    a.bytecode = deterministic_fallback_bytecode(source_text, source_path, contract_name);
    return a;
}

}
