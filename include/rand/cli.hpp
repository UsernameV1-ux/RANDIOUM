#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

namespace randio::cli {

[[nodiscard]] int run(std::span<const std::string_view> args, std::ostream& out, std::ostream& err);

}
