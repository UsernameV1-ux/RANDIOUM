#include "rand/abi/ts_bindings.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace randio::module105 {
namespace {

[[nodiscard]] std::string to_ts_ident(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
            out.push_back(c);
        } else {
            out.push_back('_');
        }
    }
    if (out.empty()) {
        out = "_";
    }
    if (out[0] >= '0' && out[0] <= '9') {
        out.insert(out.begin(), '_');
    }
    return out;
}

[[nodiscard]] std::string ts_type_for(const module104::AbiType& t);

[[nodiscard]] std::string ts_type_for_array(const module104::ArrayType& at) {
    const auto elem = ts_type_for(*at.elem);
    return elem + "[]";
}

[[nodiscard]] std::string ts_type_for_tuple(const module104::TupleType& tt) {
    std::ostringstream oss;
    oss << "{";
    for (std::size_t i = 0; i < tt.elems.size(); ++i) {
        if (i != 0) {
            oss << ", ";
        }
        oss << "f" << i << ": " << ts_type_for(*tt.elems[i]);
    }
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string ts_type_for(const module104::AbiType& t) {
    if (std::holds_alternative<module104::UintType>(t.v) || std::holds_alternative<module104::IntType>(t.v)) {
        return "string";
    }
    if (std::holds_alternative<module104::BoolType>(t.v)) {
        return "boolean";
    }
    if (std::holds_alternative<module104::AddressType>(t.v)) {
        return "string";
    }
    if (std::holds_alternative<module104::BytesNType>(t.v) || std::holds_alternative<module104::BytesType>(t.v)) {
        return "string";
    }
    if (std::holds_alternative<module104::StringType>(t.v)) {
        return "string";
    }
    if (std::holds_alternative<module104::ArrayType>(t.v)) {
        return ts_type_for_array(std::get<module104::ArrayType>(t.v));
    }
    if (std::holds_alternative<module104::TupleType>(t.v)) {
        return ts_type_for_tuple(std::get<module104::TupleType>(t.v));
    }
    return "unknown";
}

[[nodiscard]] std::string ts_string_lit(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (const char c : s) {
        if (c == '\\' || c == '\'') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

} // namespace

std::string generate_ts_bindings(std::string_view contract_name, const std::vector<TsAbiFunction>& functions) {
    const std::string cname = to_ts_ident(contract_name);

    std::ostringstream out;

    out << "export type Address = string;\n";
    out << "\n";
    out << "export class " << cname << "Client {\n";
    out << "  private baseUrl: string;\n";
    out << "\n";
    out << "  constructor(baseUrl: string) {\n";
    out << "    this.baseUrl = baseUrl.replace(/\\/+$/, '');\n";
    out << "  }\n";
    out << "\n";
    out << "  private async rpcPost(path: string, bodyObj: unknown): Promise<any> {\n";
    out << "    const url = `${this.baseUrl}${path}`;\n";
    out << "    const body = JSON.stringify(bodyObj ?? {});\n";
    out << "    const res = await fetch(url, {\n";
    out << "      method: 'POST',\n";
    out << "      headers: { 'content-type': 'application/json' },\n";
    out << "      body\n";
    out << "    });\n";
    out << "    const text = await res.text();\n";
    out << "    if (!res.ok) {\n";
    out << "      throw new Error(text || String(res.status));\n";
    out << "    }\n";
    out << "    try {\n";
    out << "      return JSON.parse(text);\n";
    out << "    } catch {\n";
    out << "      return text;\n";
    out << "    }\n";
    out << "  }\n";

    for (const auto& fn : functions) {
        const std::string m = to_ts_ident(fn.name);

        out << "\n";
        out << "  async " << m << "(from: Address, contract: Address";
        for (std::size_t i = 0; i < fn.inputs.size(); ++i) {
            const auto& p = fn.inputs[i];
            const std::string pname = to_ts_ident(p.name.empty() ? ("arg" + std::to_string(i)) : p.name);
            const std::string ptype = p.type ? ts_type_for(*p.type) : "unknown";
            out << ", " << pname << ": " << ptype;
        }
        out << "): Promise<any> {\n";

        out << "    return this.rpcPost('/tx/sendCall', {\n";
        out << "      from,\n";
        out << "      to: contract,\n";
        out << "      method: " << ts_string_lit(fn.name) << ",\n";
        out << "      args: {\n";
        for (std::size_t i = 0; i < fn.inputs.size(); ++i) {
            const auto& p = fn.inputs[i];
            const std::string pname = to_ts_ident(p.name.empty() ? ("arg" + std::to_string(i)) : p.name);
            out << "        " << pname;
            if (i + 1 != fn.inputs.size()) {
                out << ",";
            }
            out << "\n";
        }
        out << "      }\n";
        out << "    });\n";
        out << "  }\n";
    }

    out << "}\n";
    return out.str();
}

}
