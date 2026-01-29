#pragma once

#include <cstdint>
 #include <filesystem>
 #include <optional>
 #include <span>
 #include <string>
 #include <string_view>
 #include <vector>

namespace randio::module108 {

[[nodiscard]] constexpr std::uint32_t module_number() {
    return 108;
}

[[nodiscard]] int link_anchor();

 struct SolidityArtifact final {
     std::string format;
     std::string contract;
     std::string source;
     std::string compiler;
     std::string abi_json;
     std::vector<std::uint8_t> bytecode;
 };

 [[nodiscard]] std::string encode_artifact_json(const SolidityArtifact& a);
 [[nodiscard]] std::optional<SolidityArtifact> decode_artifact_json(std::string_view json);

 [[nodiscard]] bool write_artifact_file(const std::filesystem::path& p, const SolidityArtifact& a);
 [[nodiscard]] std::optional<SolidityArtifact> read_artifact_file(const std::filesystem::path& p);

 [[nodiscard]] SolidityArtifact compile_solidity_fallback(std::string_view source_text,
                                                         std::string_view source_path,
                                                         std::string_view contract_name);

}
