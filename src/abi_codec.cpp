#include "rand/abi/codec.hpp"

#include "rand/perf.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <limits>

namespace randio::module104 {
namespace {

[[nodiscard]] bool mul_overflow(const std::size_t a, const std::size_t b, std::size_t& out) {
    if (a == 0 || b == 0) {
        out = 0;
        return false;
    }
    if (a > (std::numeric_limits<std::size_t>::max)() / b) {
        return true;
    }
    out = a * b;
    return false;
}

[[nodiscard]] bool add_overflow(const std::size_t a, const std::size_t b, std::size_t& out) {
    if (a > (std::numeric_limits<std::size_t>::max)() - b) {
        return true;
    }
    out = a + b;
    return false;
}

[[nodiscard]] std::size_t ceil32(const std::size_t n) {
    const std::size_t r = n % 32;
    return (r == 0) ? n : (n + (32 - r));
}

[[nodiscard]] bool word_all_zero(std::span<const std::uint8_t> w, const std::size_t start, const std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (w[start + i] != 0) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool word_all_ff(std::span<const std::uint8_t> w, const std::size_t start, const std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (w[start + i] != 0xFFu) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool parse_word_size_t(std::span<const std::uint8_t> w, std::size_t& out) {
    const std::size_t high = 32 - sizeof(std::size_t);
    if (!word_all_zero(w, 0, high)) {
        return false;
    }
    std::size_t v = 0;
    for (std::size_t i = 0; i < sizeof(std::size_t); ++i) {
        v = (v << 8u) | static_cast<std::size_t>(w[high + i]);
    }
    out = v;
    return true;
}

void write_word_size_t(std::vector<std::uint8_t>& out, const std::size_t v) {
    std::uint8_t w[32]{};
    for (std::size_t i = 0; i < sizeof(std::size_t); ++i) {
        const std::size_t shift = 8u * (sizeof(std::size_t) - 1u - i);
        w[32 - sizeof(std::size_t) + i] = static_cast<std::uint8_t>((v >> shift) & 0xFFu);
    }
    out.insert(out.end(), w, w + 32);
}

void write_word_bytes(std::vector<std::uint8_t>& out, const std::uint8_t w[32]) {
    out.insert(out.end(), w, w + 32);
}

void write_zeros(std::vector<std::uint8_t>& out, const std::size_t n) {
    out.insert(out.end(), n, 0);
}

[[nodiscard]] bool is_valid_utf8(std::span<const std::uint8_t> b) {
    std::size_t i = 0;
    while (i < b.size()) {
        const std::uint8_t c = b[i];
        if (c <= 0x7Fu) {
            i += 1;
            continue;
        }
        if ((c & 0xE0u) == 0xC0u) {
            if (i + 1 >= b.size()) {
                return false;
            }
            const std::uint8_t c1 = b[i + 1];
            if ((c1 & 0xC0u) != 0x80u) {
                return false;
            }
            const std::uint32_t cp = ((c & 0x1Fu) << 6u) | (c1 & 0x3Fu);
            if (cp < 0x80u) {
                return false;
            }
            i += 2;
            continue;
        }
        if ((c & 0xF0u) == 0xE0u) {
            if (i + 2 >= b.size()) {
                return false;
            }
            const std::uint8_t c1 = b[i + 1];
            const std::uint8_t c2 = b[i + 2];
            if ((c1 & 0xC0u) != 0x80u || (c2 & 0xC0u) != 0x80u) {
                return false;
            }
            const std::uint32_t cp = ((c & 0x0Fu) << 12u) | ((c1 & 0x3Fu) << 6u) | (c2 & 0x3Fu);
            if (cp < 0x800u) {
                return false;
            }
            if (cp >= 0xD800u && cp <= 0xDFFFu) {
                return false;
            }
            i += 3;
            continue;
        }
        if ((c & 0xF8u) == 0xF0u) {
            if (i + 3 >= b.size()) {
                return false;
            }
            const std::uint8_t c1 = b[i + 1];
            const std::uint8_t c2 = b[i + 2];
            const std::uint8_t c3 = b[i + 3];
            if ((c1 & 0xC0u) != 0x80u || (c2 & 0xC0u) != 0x80u || (c3 & 0xC0u) != 0x80u) {
                return false;
            }
            const std::uint32_t cp = ((c & 0x07u) << 18u) | ((c1 & 0x3Fu) << 12u) | ((c2 & 0x3Fu) << 6u) | (c3 & 0x3Fu);
            if (cp < 0x10000u || cp > 0x10FFFFu) {
                return false;
            }
            i += 4;
            continue;
        }
        return false;
    }
    return true;
}

[[nodiscard]] bool valid_uint_bits(std::span<const std::uint8_t> w, const std::uint16_t bits) {
    if (bits == 0 || bits > 256 || (bits % 8u) != 0u) {
        return false;
    }
    const std::size_t keep = static_cast<std::size_t>(bits / 8u);
    const std::size_t zero = 32 - keep;
    return word_all_zero(w, 0, zero);
}

[[nodiscard]] bool valid_int_bits(std::span<const std::uint8_t> w, const std::uint16_t bits) {
    if (bits == 0 || bits > 256 || (bits % 8u) != 0u) {
        return false;
    }
    if (bits == 256) {
        return true;
    }
    const std::size_t keep = static_cast<std::size_t>(bits / 8u);
    const std::size_t high = 32 - keep;
    const bool neg = (w[high] & 0x80u) != 0;
    return neg ? word_all_ff(w, 0, high) : word_all_zero(w, 0, high);
}

[[nodiscard]] EncodeStatus encode_tuple_like(const std::vector<std::shared_ptr<AbiType>>& ts,
                                            const std::vector<std::shared_ptr<AbiValue>>& vs,
                                            std::vector<std::uint8_t>& out,
                                            const EncodeOptions& opt,
                                            const std::size_t depth);

[[nodiscard]] DecodeStatus decode_tuple_like(const std::vector<std::shared_ptr<AbiType>>& ts,
                                            std::span<const std::uint8_t> bytes,
                                            std::vector<std::shared_ptr<AbiValue>>& out,
                                            std::size_t& consumed,
                                            const DecodeOptions& opt,
                                            const std::size_t depth);

[[nodiscard]] bool dynamic_any(const TupleType& t) {
    for (const auto& e : t.elems) {
        if (is_dynamic(*e)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] EncodeStatus encode_static(const AbiType& t, const AbiValue& v, std::vector<std::uint8_t>& out, const EncodeOptions& opt, const std::size_t depth);
[[nodiscard]] EncodeStatus encode_dynamic(const AbiType& t, const AbiValue& v, std::vector<std::uint8_t>& out, const EncodeOptions& opt, const std::size_t depth);

[[nodiscard]] DecodeStatus decode_static(const AbiType& t, std::span<const std::uint8_t> bytes, AbiValue& out, const DecodeOptions& opt, const std::size_t depth);
[[nodiscard]] DecodeStatus decode_dynamic(const AbiType& t, std::span<const std::uint8_t> bytes, AbiValue& out, std::size_t& consumed, const DecodeOptions& opt, const std::size_t depth);

[[nodiscard]] EncodeStatus encode_tuple_like(const std::vector<std::shared_ptr<AbiType>>& ts,
                                            const std::vector<std::shared_ptr<AbiValue>>& vs,
                                            std::vector<std::uint8_t>& out,
                                            const EncodeOptions& opt,
                                            const std::size_t depth) {
    if (depth > opt.max_depth) {
        return EncodeStatus::DepthLimit;
    }
    if (ts.size() != vs.size()) {
        return EncodeStatus::TypeMismatch;
    }

    std::size_t head_total = 0;
    for (const auto& t : ts) {
        const std::size_t sz = is_dynamic(*t) ? 32 : static_size_bytes(*t);
        std::size_t tmp = 0;
        if (add_overflow(head_total, sz, tmp)) {
            return EncodeStatus::SizeLimit;
        }
        head_total = tmp;
    }

    std::vector<std::uint8_t> head;
    head.reserve(head_total);
    std::vector<std::uint8_t> tail;

    for (std::size_t i = 0; i < ts.size(); ++i) {
        const auto& t = *ts[i];
        const auto& v = *vs[i];

        if (is_dynamic(t)) {
            const std::size_t off = head_total + tail.size();
            write_word_size_t(head, off);
            const auto st = encode_dynamic(t, v, tail, opt, depth + 1);
            if (st != EncodeStatus::Ok) {
                return st;
            }
        } else {
            const auto st = encode_static(t, v, head, opt, depth + 1);
            if (st != EncodeStatus::Ok) {
                return st;
            }
        }

        if (head.size() > opt.max_total_bytes || tail.size() > opt.max_total_bytes) {
            return EncodeStatus::SizeLimit;
        }
    }

    out.insert(out.end(), head.begin(), head.end());
    out.insert(out.end(), tail.begin(), tail.end());
    if (out.size() > opt.max_total_bytes) {
        return EncodeStatus::SizeLimit;
    }
    return EncodeStatus::Ok;
}

[[nodiscard]] EncodeStatus encode_static(const AbiType& t, const AbiValue& v, std::vector<std::uint8_t>& out, const EncodeOptions& opt, const std::size_t depth) {
    if (depth > opt.max_depth) {
        return EncodeStatus::DepthLimit;
    }

    if (std::holds_alternative<UintType>(t.v)) {
        if (!std::holds_alternative<UintValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto bits = std::get<UintType>(t.v).bits;
        const auto& w = std::get<UintValue>(v.v).word;
        if (!valid_uint_bits(std::span<const std::uint8_t>(w.data(), w.size()), bits)) {
            return EncodeStatus::NotCanonical;
        }
        write_word_bytes(out, w.data());
        return EncodeStatus::Ok;
    }

    if (std::holds_alternative<IntType>(t.v)) {
        if (!std::holds_alternative<IntValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto bits = std::get<IntType>(t.v).bits;
        const auto& w = std::get<IntValue>(v.v).word;
        if (!valid_int_bits(std::span<const std::uint8_t>(w.data(), w.size()), bits)) {
            return EncodeStatus::NotCanonical;
        }
        write_word_bytes(out, w.data());
        return EncodeStatus::Ok;
    }

    if (std::holds_alternative<BoolType>(t.v)) {
        if (!std::holds_alternative<BoolValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const bool b = std::get<BoolValue>(v.v).v;
        std::uint8_t w[32]{};
        w[31] = static_cast<std::uint8_t>(b ? 1 : 0);
        write_word_bytes(out, w);
        return EncodeStatus::Ok;
    }

    if (std::holds_alternative<AddressType>(t.v)) {
        if (!std::holds_alternative<AddressValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto& a = std::get<AddressValue>(v.v).v;
        std::uint8_t w[32]{};
        std::memcpy(w + 12, a.data(), a.size());
        write_word_bytes(out, w);
        return EncodeStatus::Ok;
    }

    if (std::holds_alternative<BytesNType>(t.v)) {
        if (!std::holds_alternative<BytesNValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto n = static_cast<std::size_t>(std::get<BytesNType>(t.v).n);
        const auto& b = std::get<BytesNValue>(v.v).bytes;
        if (b.size() != n) {
            return EncodeStatus::TypeMismatch;
        }
        std::uint8_t w[32]{};
        std::memcpy(w, b.data(), b.size());
        write_word_bytes(out, w);
        return EncodeStatus::Ok;
    }

    if (std::holds_alternative<ArrayType>(t.v)) {
        const auto& at = std::get<ArrayType>(t.v);
        if (!at.fixed_len) {
            return EncodeStatus::TypeMismatch;
        }
        if (!std::holds_alternative<ArrayValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto& av = std::get<ArrayValue>(v.v);
        if (av.elems.size() != *at.fixed_len) {
            return EncodeStatus::TypeMismatch;
        }
        if (is_dynamic(*at.elem)) {
            return EncodeStatus::TypeMismatch;
        }
        for (const auto& e : av.elems) {
            const auto st = encode_static(*at.elem, *e, out, opt, depth + 1);
            if (st != EncodeStatus::Ok) {
                return st;
            }
        }
        return EncodeStatus::Ok;
    }

    if (std::holds_alternative<TupleType>(t.v)) {
        const auto& tt = std::get<TupleType>(t.v);
        if (dynamic_any(tt)) {
            return EncodeStatus::TypeMismatch;
        }
        if (!std::holds_alternative<TupleValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto& tv = std::get<TupleValue>(v.v);
        if (tv.elems.size() != tt.elems.size()) {
            return EncodeStatus::TypeMismatch;
        }
        for (std::size_t i = 0; i < tt.elems.size(); ++i) {
            const auto st = encode_static(*tt.elems[i], *tv.elems[i], out, opt, depth + 1);
            if (st != EncodeStatus::Ok) {
                return st;
            }
        }
        return EncodeStatus::Ok;
    }

    if (std::holds_alternative<BytesType>(t.v) || std::holds_alternative<StringType>(t.v)) {
        return EncodeStatus::TypeMismatch;
    }

    return EncodeStatus::TypeMismatch;
}

[[nodiscard]] EncodeStatus encode_dynamic(const AbiType& t, const AbiValue& v, std::vector<std::uint8_t>& out, const EncodeOptions& opt, const std::size_t depth) {
    if (depth > opt.max_depth) {
        return EncodeStatus::DepthLimit;
    }

    if (std::holds_alternative<BytesType>(t.v)) {
        if (!std::holds_alternative<BytesValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto& b = std::get<BytesValue>(v.v).bytes;
        write_word_size_t(out, b.size());
        out.insert(out.end(), b.begin(), b.end());
        const std::size_t pad = ceil32(b.size()) - b.size();
        write_zeros(out, pad);
        return EncodeStatus::Ok;
    }

    if (std::holds_alternative<StringType>(t.v)) {
        if (!std::holds_alternative<StringValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto& s = std::get<StringValue>(v.v).s;
        write_word_size_t(out, s.size());
        out.insert(out.end(), reinterpret_cast<const std::uint8_t*>(s.data()), reinterpret_cast<const std::uint8_t*>(s.data()) + s.size());
        const std::size_t pad = ceil32(s.size()) - s.size();
        write_zeros(out, pad);
        return EncodeStatus::Ok;
    }

    if (std::holds_alternative<ArrayType>(t.v)) {
        const auto& at = std::get<ArrayType>(t.v);
        if (!std::holds_alternative<ArrayValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto& av = std::get<ArrayValue>(v.v);
        if (av.elems.size() > opt.max_array_elems) {
            return EncodeStatus::SizeLimit;
        }

        if (!at.fixed_len) {
            write_word_size_t(out, av.elems.size());
            std::vector<std::shared_ptr<AbiType>> ts;
            ts.resize(av.elems.size(), at.elem);
            const auto st = encode_tuple_like(ts, av.elems, out, opt, depth + 1);
            return st;
        }

        if (av.elems.size() != *at.fixed_len) {
            return EncodeStatus::TypeMismatch;
        }

        std::vector<std::shared_ptr<AbiType>> ts;
        ts.resize(av.elems.size(), at.elem);
        const auto st = encode_tuple_like(ts, av.elems, out, opt, depth + 1);
        return st;
    }

    if (std::holds_alternative<TupleType>(t.v)) {
        const auto& tt = std::get<TupleType>(t.v);
        if (!std::holds_alternative<TupleValue>(v.v)) {
            return EncodeStatus::TypeMismatch;
        }
        const auto& tv = std::get<TupleValue>(v.v);
        if (tv.elems.size() != tt.elems.size()) {
            return EncodeStatus::TypeMismatch;
        }
        const auto st = encode_tuple_like(tt.elems, tv.elems, out, opt, depth + 1);
        return st;
    }

    if (std::holds_alternative<UintType>(t.v) || std::holds_alternative<IntType>(t.v) || std::holds_alternative<BoolType>(t.v) ||
        std::holds_alternative<AddressType>(t.v) || std::holds_alternative<BytesNType>(t.v)) {
        return EncodeStatus::TypeMismatch;
    }

    return EncodeStatus::TypeMismatch;
}

[[nodiscard]] DecodeStatus decode_static(const AbiType& t, std::span<const std::uint8_t> bytes, AbiValue& out, const DecodeOptions& opt, const std::size_t depth) {
    if (depth > opt.max_depth) {
        return DecodeStatus::DepthLimit;
    }
    if (bytes.size() < 32) {
        return DecodeStatus::TooShort;
    }

    if (std::holds_alternative<UintType>(t.v)) {
        const auto bits = std::get<UintType>(t.v).bits;
        if (!valid_uint_bits(bytes.subspan(0, 32), bits)) {
            return DecodeStatus::NotCanonical;
        }
        UintValue uv;
        std::memcpy(uv.word.data(), bytes.data(), 32);
        out.v = uv;
        return DecodeStatus::Ok;
    }

    if (std::holds_alternative<IntType>(t.v)) {
        const auto bits = std::get<IntType>(t.v).bits;
        if (!valid_int_bits(bytes.subspan(0, 32), bits)) {
            return DecodeStatus::NotCanonical;
        }
        IntValue iv;
        std::memcpy(iv.word.data(), bytes.data(), 32);
        out.v = iv;
        return DecodeStatus::Ok;
    }

    if (std::holds_alternative<BoolType>(t.v)) {
        std::size_t v = 0;
        if (!parse_word_size_t(bytes.subspan(0, 32), v)) {
            return DecodeStatus::InvalidWord;
        }
        if (v != 0 && v != 1) {
            return DecodeStatus::NotCanonical;
        }
        out.v = BoolValue{v == 1};
        return DecodeStatus::Ok;
    }

    if (std::holds_alternative<AddressType>(t.v)) {
        if (!word_all_zero(bytes.subspan(0, 32), 0, 12)) {
            return DecodeStatus::NotCanonical;
        }
        AddressValue av;
        std::memcpy(av.v.data(), bytes.data() + 12, 20);
        out.v = av;
        return DecodeStatus::Ok;
    }

    if (std::holds_alternative<BytesNType>(t.v)) {
        const auto n = static_cast<std::size_t>(std::get<BytesNType>(t.v).n);
        if (n == 0 || n > 32) {
            return DecodeStatus::TypeMismatch;
        }
        if (!word_all_zero(bytes.subspan(0, 32), n, 32 - n)) {
            return DecodeStatus::NotCanonical;
        }
        BytesNValue bv;
        bv.bytes.assign(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(n));
        out.v = bv;
        return DecodeStatus::Ok;
    }

    if (std::holds_alternative<ArrayType>(t.v)) {
        const auto& at = std::get<ArrayType>(t.v);
        if (!at.fixed_len) {
            return DecodeStatus::TypeMismatch;
        }
        if (is_dynamic(*at.elem)) {
            return DecodeStatus::TypeMismatch;
        }

        const auto elem_sz = static_size_bytes(*at.elem);
        std::size_t need = 0;
        if (mul_overflow(*at.fixed_len, elem_sz, need)) {
            return DecodeStatus::SizeLimit;
        }
        if (bytes.size() < need) {
            return DecodeStatus::TooShort;
        }

        ArrayValue av;
        av.elems.reserve(*at.fixed_len);
        std::size_t off = 0;
        for (std::size_t i = 0; i < *at.fixed_len; ++i) {
            AbiValue ev;
            const auto st = decode_static(*at.elem, bytes.subspan(off), ev, opt, depth + 1);
            if (st != DecodeStatus::Ok) {
                return st;
            }
            auto pv = std::make_shared<AbiValue>();
            pv->v = ev.v;
            av.elems.push_back(std::move(pv));
            off += elem_sz;
        }
        out.v = av;
        return DecodeStatus::Ok;
    }

    if (std::holds_alternative<TupleType>(t.v)) {
        const auto& tt = std::get<TupleType>(t.v);
        if (dynamic_any(tt)) {
            return DecodeStatus::TypeMismatch;
        }

        TupleValue tv;
        tv.elems.reserve(tt.elems.size());
        std::size_t off = 0;
        for (const auto& e : tt.elems) {
            const auto sz = static_size_bytes(*e);
            if (bytes.size() < off + sz) {
                return DecodeStatus::TooShort;
            }
            AbiValue ev;
            const auto st = decode_static(*e, bytes.subspan(off), ev, opt, depth + 1);
            if (st != DecodeStatus::Ok) {
                return st;
            }
            auto pv = std::make_shared<AbiValue>();
            pv->v = ev.v;
            tv.elems.push_back(std::move(pv));
            off += sz;
        }
        out.v = tv;
        return DecodeStatus::Ok;
    }

    return DecodeStatus::TypeMismatch;
}

[[nodiscard]] DecodeStatus decode_dynamic(const AbiType& t, std::span<const std::uint8_t> bytes, AbiValue& out, std::size_t& consumed, const DecodeOptions& opt, const std::size_t depth) {
    if (depth > opt.max_depth) {
        return DecodeStatus::DepthLimit;
    }
    if (bytes.size() > opt.max_total_bytes) {
        return DecodeStatus::SizeLimit;
    }
    if (bytes.size() < 32) {
        return DecodeStatus::TooShort;
    }

    if (std::holds_alternative<BytesType>(t.v)) {
        std::size_t n = 0;
        if (!parse_word_size_t(bytes.subspan(0, 32), n)) {
            return DecodeStatus::InvalidLength;
        }
        if (n > opt.max_total_bytes) {
            return DecodeStatus::SizeLimit;
        }
        const std::size_t need = 32 + ceil32(n);
        if (bytes.size() < need) {
            return DecodeStatus::TooShort;
        }
        if (!word_all_zero(bytes.subspan(0, need), 32 + n, need - (32 + n))) {
            return DecodeStatus::NotCanonical;
        }
        BytesValue bv;
        bv.bytes.assign(bytes.begin() + 32, bytes.begin() + 32 + static_cast<std::ptrdiff_t>(n));
        out.v = bv;
        consumed = need;
        return DecodeStatus::Ok;
    }

    if (std::holds_alternative<StringType>(t.v)) {
        std::size_t n = 0;
        if (!parse_word_size_t(bytes.subspan(0, 32), n)) {
            return DecodeStatus::InvalidLength;
        }
        if (n > opt.max_total_bytes) {
            return DecodeStatus::SizeLimit;
        }
        const std::size_t need = 32 + ceil32(n);
        if (bytes.size() < need) {
            return DecodeStatus::TooShort;
        }
        if (!word_all_zero(bytes.subspan(0, need), 32 + n, need - (32 + n))) {
            return DecodeStatus::NotCanonical;
        }
        const auto payload = bytes.subspan(32, n);
        if (!is_valid_utf8(payload)) {
            return DecodeStatus::InvalidUtf8;
        }
        StringValue sv;
        sv.s.assign(reinterpret_cast<const char*>(payload.data()), payload.size());
        out.v = sv;
        consumed = need;
        return DecodeStatus::Ok;
    }

    if (std::holds_alternative<ArrayType>(t.v)) {
        const auto& at = std::get<ArrayType>(t.v);
        std::size_t off = 0;
        if (!at.fixed_len) {
            std::size_t n = 0;
            if (!parse_word_size_t(bytes.subspan(0, 32), n)) {
                return DecodeStatus::InvalidLength;
            }
            if (n > opt.max_array_elems) {
                return DecodeStatus::SizeLimit;
            }
            off = 32;

            std::vector<std::shared_ptr<AbiType>> ts;
            ts.resize(n, at.elem);
            std::vector<std::shared_ptr<AbiValue>> vs;
            std::size_t sub = 0;
            const auto st = decode_tuple_like(ts, bytes.subspan(off), vs, sub, opt, depth + 1);
            if (st != DecodeStatus::Ok) {
                return st;
            }
            ArrayValue av;
            av.elems = std::move(vs);
            out.v = av;
            consumed = off + sub;
            return DecodeStatus::Ok;
        }

        const std::size_t n = *at.fixed_len;
        if (n > opt.max_array_elems) {
            return DecodeStatus::SizeLimit;
        }
        std::vector<std::shared_ptr<AbiType>> ts;
        ts.resize(n, at.elem);
        std::vector<std::shared_ptr<AbiValue>> vs;
        std::size_t sub = 0;
        const auto st = decode_tuple_like(ts, bytes, vs, sub, opt, depth + 1);
        if (st != DecodeStatus::Ok) {
            return st;
        }
        ArrayValue av;
        av.elems = std::move(vs);
        out.v = av;
        consumed = sub;
        return DecodeStatus::Ok;
    }

    if (std::holds_alternative<TupleType>(t.v)) {
        const auto& tt = std::get<TupleType>(t.v);
        std::vector<std::shared_ptr<AbiValue>> vs;
        std::size_t sub = 0;
        const auto st = decode_tuple_like(tt.elems, bytes, vs, sub, opt, depth + 1);
        if (st != DecodeStatus::Ok) {
            return st;
        }
        TupleValue tv;
        tv.elems = std::move(vs);
        out.v = tv;
        consumed = sub;
        return DecodeStatus::Ok;
    }

    return DecodeStatus::TypeMismatch;
}

struct DynRange final {
    std::size_t start{0};
    std::size_t end{0};
};

[[nodiscard]] DecodeStatus decode_tuple_like(const std::vector<std::shared_ptr<AbiType>>& ts,
                                            std::span<const std::uint8_t> bytes,
                                            std::vector<std::shared_ptr<AbiValue>>& out,
                                            std::size_t& consumed,
                                            const DecodeOptions& opt,
                                            const std::size_t depth) {
    if (depth > opt.max_depth) {
        return DecodeStatus::DepthLimit;
    }
    if (bytes.size() > opt.max_total_bytes) {
        return DecodeStatus::SizeLimit;
    }

    std::size_t head_total = 0;
    for (const auto& t : ts) {
        const std::size_t sz = is_dynamic(*t) ? 32 : static_size_bytes(*t);
        std::size_t tmp = 0;
        if (add_overflow(head_total, sz, tmp)) {
            return DecodeStatus::SizeLimit;
        }
        head_total = tmp;
    }

    if (bytes.size() < head_total) {
        return DecodeStatus::TooShort;
    }

    out.clear();
    out.reserve(ts.size());

    std::vector<std::optional<std::size_t>> dyn_off;
    dyn_off.resize(ts.size());

    std::size_t cursor = 0;
    for (std::size_t i = 0; i < ts.size(); ++i) {
        const auto& t = *ts[i];
        if (is_dynamic(t)) {
            std::size_t off = 0;
            if (!parse_word_size_t(bytes.subspan(cursor, 32), off)) {
                return DecodeStatus::InvalidOffset;
            }
            dyn_off[i] = off;
            cursor += 32;
            out.push_back(std::make_shared<AbiValue>());
            continue;
        }

        AbiValue v;
        const auto st = decode_static(t, bytes.subspan(cursor), v, opt, depth + 1);
        if (st != DecodeStatus::Ok) {
            return st;
        }
        const auto pv = std::make_shared<AbiValue>();
        pv->v = v.v;
        out.push_back(pv);
        cursor += static_size_bytes(t);
    }

    std::vector<DynRange> ranges;

    for (std::size_t i = 0; i < ts.size(); ++i) {
        if (!dyn_off[i]) {
            continue;
        }

        const auto& t = *ts[i];
        const std::size_t off = *dyn_off[i];
        if ((off % 32u) != 0u) {
            return DecodeStatus::InvalidOffset;
        }
        if (off < head_total || off >= bytes.size()) {
            return DecodeStatus::InvalidOffset;
        }

        AbiValue dv;
        std::size_t dcons = 0;
        const auto st = decode_dynamic(t, bytes.subspan(off), dv, dcons, opt, depth + 1);
        if (st != DecodeStatus::Ok) {
            return st;
        }

        const std::size_t end = off + dcons;
        if (end > bytes.size()) {
            return DecodeStatus::TooShort;
        }

        const auto pv = std::make_shared<AbiValue>();
        pv->v = dv.v;
        out[i] = pv;
        ranges.push_back({off, end});
    }

    if (opt.require_canonical_offsets && !ranges.empty()) {
        std::sort(ranges.begin(), ranges.end(), [](const DynRange& a, const DynRange& b) { return a.start < b.start; });
        std::size_t prev_end = head_total;
        for (const auto& r : ranges) {
            if (r.start < prev_end) {
                return DecodeStatus::NotCanonical;
            }
            prev_end = r.end;
        }
        consumed = prev_end;
    } else {
        std::size_t max_end = head_total;
        for (const auto& r : ranges) {
            max_end = (std::max)(max_end, r.end);
        }
        consumed = max_end;
    }

    return DecodeStatus::Ok;
}

}

bool is_dynamic(const AbiType& t) {
    if (std::holds_alternative<BytesType>(t.v) || std::holds_alternative<StringType>(t.v)) {
        return true;
    }
    if (std::holds_alternative<ArrayType>(t.v)) {
        const auto& a = std::get<ArrayType>(t.v);
        if (!a.fixed_len) {
            return true;
        }
        return is_dynamic(*a.elem);
    }
    if (std::holds_alternative<TupleType>(t.v)) {
        return dynamic_any(std::get<TupleType>(t.v));
    }
    return false;
}

std::size_t static_size_bytes(const AbiType& t) {
    if (std::holds_alternative<UintType>(t.v) || std::holds_alternative<IntType>(t.v) || std::holds_alternative<BoolType>(t.v) ||
        std::holds_alternative<AddressType>(t.v) || std::holds_alternative<BytesNType>(t.v)) {
        return 32;
    }

    if (std::holds_alternative<ArrayType>(t.v)) {
        const auto& a = std::get<ArrayType>(t.v);
        if (!a.fixed_len) {
            return 32;
        }
        if (is_dynamic(*a.elem)) {
            return 32;
        }
        std::size_t prod = 0;
        if (mul_overflow(*a.fixed_len, static_size_bytes(*a.elem), prod)) {
            return 32;
        }
        return prod;
    }

    if (std::holds_alternative<TupleType>(t.v)) {
        const auto& tt = std::get<TupleType>(t.v);
        if (dynamic_any(tt)) {
            return 32;
        }
        std::size_t sum = 0;
        for (const auto& e : tt.elems) {
            const auto sz = static_size_bytes(*e);
            std::size_t tmp = 0;
            if (add_overflow(sum, sz, tmp)) {
                return 32;
            }
            sum = tmp;
        }
        return sum;
    }

    return 32;
}

EncodeStatus encode_value(const AbiType& t, const AbiValue& v, std::vector<std::uint8_t>& out, const EncodeOptions& opt) {
    const std::size_t depth = 0;
    if (is_dynamic(t)) {
        std::vector<std::shared_ptr<AbiType>> ts = {std::make_shared<AbiType>(t)};
        std::vector<std::shared_ptr<AbiValue>> vs = {std::make_shared<AbiValue>(v)};
        return encode_tuple_like(ts, vs, out, opt, depth);
    }
    return encode_static(t, v, out, opt, depth);
}

EncodeStatus encode_params(const std::vector<std::shared_ptr<AbiType>>& types,
                          const std::vector<std::shared_ptr<AbiValue>>& values,
                          std::vector<std::uint8_t>& out,
                          const EncodeOptions& opt) {
    return encode_tuple_like(types, values, out, opt, 0);
}

std::optional<std::vector<std::uint8_t>> encode_params(const std::vector<std::shared_ptr<AbiType>>& types,
                                                       const std::vector<std::shared_ptr<AbiValue>>& values,
                                                       const EncodeOptions& opt) {
    std::vector<std::uint8_t> out;
    out.reserve(32 * types.size());
    const auto st = encode_params(types, values, out, opt);
    if (st != EncodeStatus::Ok) {
        return std::nullopt;
    }
    return out;
}

DecodeStatus decode_value(const AbiType& t, std::span<const std::uint8_t> bytes, AbiValue& out, std::size_t& consumed, const DecodeOptions& opt) {
    if (is_dynamic(t)) {
        std::vector<std::shared_ptr<AbiType>> ts = {std::make_shared<AbiType>(t)};
        std::vector<std::shared_ptr<AbiValue>> vs;
        std::size_t c = 0;
        const auto st = decode_tuple_like(ts, bytes, vs, c, opt, 0);
        if (st != DecodeStatus::Ok) {
            return st;
        }
        if (vs.size() != 1) {
            return DecodeStatus::TypeMismatch;
        }
        out.v = vs[0]->v;
        consumed = c;
        return DecodeStatus::Ok;
    }

    if (bytes.size() < 32) {
        return DecodeStatus::TooShort;
    }
    const auto st = decode_static(t, bytes, out, opt, 0);
    if (st != DecodeStatus::Ok) {
        return st;
    }
    consumed = static_size_bytes(t);
    return DecodeStatus::Ok;
}

DecodeStatus decode_params(const std::vector<std::shared_ptr<AbiType>>& types,
                          std::span<const std::uint8_t> bytes,
                          std::vector<std::shared_ptr<AbiValue>>& out,
                          std::size_t& consumed,
                          const DecodeOptions& opt) {
    return decode_tuple_like(types, bytes, out, consumed, opt, 0);
}

std::shared_ptr<AbiType> t_uint(const std::uint16_t bits) {
    auto t = std::make_shared<AbiType>();
    t->v = UintType{bits};
    return t;
}

std::shared_ptr<AbiType> t_int(const std::uint16_t bits) {
    auto t = std::make_shared<AbiType>();
    t->v = IntType{bits};
    return t;
}

std::shared_ptr<AbiType> t_bool() {
    auto t = std::make_shared<AbiType>();
    t->v = BoolType{};
    return t;
}

std::shared_ptr<AbiType> t_address() {
    auto t = std::make_shared<AbiType>();
    t->v = AddressType{};
    return t;
}

std::shared_ptr<AbiType> t_bytes_n(const std::uint16_t n) {
    auto t = std::make_shared<AbiType>();
    t->v = BytesNType{n};
    return t;
}

std::shared_ptr<AbiType> t_bytes() {
    auto t = std::make_shared<AbiType>();
    t->v = BytesType{};
    return t;
}

std::shared_ptr<AbiType> t_string() {
    auto t = std::make_shared<AbiType>();
    t->v = StringType{};
    return t;
}

std::shared_ptr<AbiType> t_array(std::shared_ptr<AbiType> elem) {
    auto t = std::make_shared<AbiType>();
    ArrayType a;
    a.elem = std::move(elem);
    a.fixed_len = std::nullopt;
    t->v = a;
    return t;
}

std::shared_ptr<AbiType> t_array(std::shared_ptr<AbiType> elem, const std::size_t fixed_len) {
    auto t = std::make_shared<AbiType>();
    ArrayType a;
    a.elem = std::move(elem);
    a.fixed_len = fixed_len;
    t->v = a;
    return t;
}

std::shared_ptr<AbiType> t_tuple(std::vector<std::shared_ptr<AbiType>> elems) {
    auto t = std::make_shared<AbiType>();
    TupleType tt;
    for (auto& e : elems) {
        tt.elems.push_back(std::move(e));
    }
    t->v = tt;
    return t;
}

std::shared_ptr<AbiValue> v_uint(const AbiWord& w) {
    auto v = std::make_shared<AbiValue>();
    v->v = UintValue{w};
    return v;
}

std::shared_ptr<AbiValue> v_int(const AbiWord& w) {
    auto v = std::make_shared<AbiValue>();
    v->v = IntValue{w};
    return v;
}

std::shared_ptr<AbiValue> v_bool(const bool b) {
    auto v = std::make_shared<AbiValue>();
    v->v = BoolValue{b};
    return v;
}

std::shared_ptr<AbiValue> v_address(const AbiAddress& a) {
    auto v = std::make_shared<AbiValue>();
    v->v = AddressValue{a};
    return v;
}

std::shared_ptr<AbiValue> v_bytes_n(std::vector<std::uint8_t> b) {
    auto v = std::make_shared<AbiValue>();
    BytesNValue bn;
    bn.bytes = std::move(b);
    v->v = bn;
    return v;
}

std::shared_ptr<AbiValue> v_bytes(std::vector<std::uint8_t> b) {
    auto v = std::make_shared<AbiValue>();
    BytesValue bv;
    bv.bytes = std::move(b);
    v->v = bv;
    return v;
}

std::shared_ptr<AbiValue> v_string(std::string s) {
    auto v = std::make_shared<AbiValue>();
    StringValue sv;
    sv.s = std::move(s);
    v->v = sv;
    return v;
}

std::shared_ptr<AbiValue> v_array(std::vector<std::shared_ptr<AbiValue>> elems) {
    auto v = std::make_shared<AbiValue>();
    ArrayValue av;
    av.elems = std::move(elems);
    v->v = av;
    return v;
}

std::shared_ptr<AbiValue> v_tuple(std::vector<std::shared_ptr<AbiValue>> elems) {
    auto v = std::make_shared<AbiValue>();
    TupleValue tv;
    tv.elems = std::move(elems);
    v->v = tv;
    return v;
}

bool abi_equal(const AbiValue& a, const AbiValue& b) {
    if (a.v.index() != b.v.index()) {
        return false;
    }

    if (std::holds_alternative<UintValue>(a.v)) {
        return std::get<UintValue>(a.v).word == std::get<UintValue>(b.v).word;
    }
    if (std::holds_alternative<IntValue>(a.v)) {
        return std::get<IntValue>(a.v).word == std::get<IntValue>(b.v).word;
    }
    if (std::holds_alternative<BoolValue>(a.v)) {
        return std::get<BoolValue>(a.v).v == std::get<BoolValue>(b.v).v;
    }
    if (std::holds_alternative<AddressValue>(a.v)) {
        return std::get<AddressValue>(a.v).v == std::get<AddressValue>(b.v).v;
    }
    if (std::holds_alternative<BytesNValue>(a.v)) {
        return std::get<BytesNValue>(a.v).bytes == std::get<BytesNValue>(b.v).bytes;
    }
    if (std::holds_alternative<BytesValue>(a.v)) {
        return std::get<BytesValue>(a.v).bytes == std::get<BytesValue>(b.v).bytes;
    }
    if (std::holds_alternative<StringValue>(a.v)) {
        return std::get<StringValue>(a.v).s == std::get<StringValue>(b.v).s;
    }
    if (std::holds_alternative<ArrayValue>(a.v)) {
        const auto& av = std::get<ArrayValue>(a.v);
        const auto& bv = std::get<ArrayValue>(b.v);
        if (av.elems.size() != bv.elems.size()) {
            return false;
        }
        for (std::size_t i = 0; i < av.elems.size(); ++i) {
            if (!abi_equal(*av.elems[i], *bv.elems[i])) {
                return false;
            }
        }
        return true;
    }
    if (std::holds_alternative<TupleValue>(a.v)) {
        const auto& av = std::get<TupleValue>(a.v);
        const auto& bv = std::get<TupleValue>(b.v);
        if (av.elems.size() != bv.elems.size()) {
            return false;
        }
        for (std::size_t i = 0; i < av.elems.size(); ++i) {
            if (!abi_equal(*av.elems[i], *bv.elems[i])) {
                return false;
            }
        }
        return true;
    }
    return false;
}

}
