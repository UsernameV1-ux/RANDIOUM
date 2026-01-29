#include "rand/bridge/light_verify.hpp"

#include "rand/chain_db.hpp"
#include "rand/consensus/checkpoint.hpp"
#include "rand/tx.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace randio::module115 {
namespace {

[[nodiscard]] module83::VerifyStatus map_status_(const module83::VerifyStatus st) {
    return st;
}

} // namespace

VerifyOutput verify_message_light(const VerifyInput& in, const VerifyOptions& opt) {
    VerifyOutput out;

    const auto msg = decode_message_v2(in.message_bytes, opt.msg_decode);
    if (!msg) {
        out.code = VerifyCode::DecodeMessageError;
        return out;
    }

    const auto enc = encode_message_v2(*msg, opt.msg_decode);
    if (!enc || enc->size() != in.message_bytes.size() ||
        !std::equal(enc->begin(), enc->end(), in.message_bytes.begin())) {
        out.code = VerifyCode::NonCanonicalMessage;
        return out;
    }

    out.msg_id = message_id_v2(*msg, opt.msg_decode);

    if (in.checkpoints.empty()) {
        out.code = VerifyCode::MissingCheckpoint;
        return out;
    }

    module83::LightClientVerifier v(opt.lc);
    v.set_checkpoints(std::vector<module82::Checkpoint>(in.checkpoints.begin(), in.checkpoints.end()));

    for (const auto& h : in.headers) {
        const auto st = v.add_header(h);
        if (st != module82::AddStatus::Ok && st != module82::AddStatus::Duplicate) {
            out.code = VerifyCode::HeaderRejected;
            return out;
        }
    }

    if (in.receipt_inclusion_proof_bytes) {
        if (!in.trusted_receipt_root.has_value()) {
            out.code = VerifyCode::MissingCheckpoint;
            return out;
        }

        module80::ReceiptInclusionProof rp;
        std::size_t consumed = 0;
        const auto dst = module80::decode_receipt_inclusion_proof(*in.receipt_inclusion_proof_bytes, rp, consumed, opt.lc.proof_decode);
        if (dst != module80::DecodeStatus::Ok || consumed != in.receipt_inclusion_proof_bytes->size()) {
            out.code = VerifyCode::ReceiptProofDecodeError;
            return out;
        }

        out.proof_height = rp.header.height;
        v.set_trusted_receipt_root(rp.header.height, *in.trusted_receipt_root);

        const auto vst = v.verify_receipt_inclusion_proof(rp);
        if (map_status_(vst) != module83::VerifyStatus::Ok) {
            out.code = VerifyCode::ReceiptProofInvalid;
            return out;
        }

        out.code = VerifyCode::Ok;
        return out;
    }

    if (!in.tx_inclusion_proof_bytes) {
        out.code = VerifyCode::MissingTxProof;
        return out;
    }

    module80::TxInclusionProof tp;
    std::size_t consumed = 0;
    const auto dst = module80::decode_tx_inclusion_proof(*in.tx_inclusion_proof_bytes, tp, consumed, opt.lc.proof_decode);
    if (dst != module80::DecodeStatus::Ok || consumed != in.tx_inclusion_proof_bytes->size()) {
        out.code = VerifyCode::TxProofDecodeError;
        return out;
    }

    out.proof_height = tp.header.height;

    const auto tx_expected = crypto::to_hex(out.msg_id);
    const auto tx_payload = std::string_view(reinterpret_cast<const char*>(tp.tx.payload.data()), tp.tx.payload.size());
    if (tx_payload != tx_expected) {
        out.code = VerifyCode::TxPayloadMismatch;
        return out;
    }

    const auto vst = v.verify_tx_inclusion_proof(tp);
    if (map_status_(vst) != module83::VerifyStatus::Ok) {
        out.code = VerifyCode::TxProofInvalid;
        return out;
    }

    out.code = VerifyCode::Ok;
    return out;
}

}

namespace randio::bridge::module115 {
namespace {

[[nodiscard]] VerifyResult vr_err_(const VerifyError e, const crypto::Hash256& id) {
    VerifyResult r;
    r.err = e;
    r.msg_id = id;
    return r;
}

[[nodiscard]] std::vector<BlockHeader> load_headers_upto_(const ChainDB& db, const std::uint64_t height) {
    std::vector<BlockHeader> out;
    out.reserve(static_cast<std::size_t>(height + 1));
    for (std::uint64_t h = 0; h <= height; ++h) {
        const auto hdr = db.header_by_height(h);
        if (!hdr) {
            break;
        }
        out.push_back(*hdr);
    }
    return out;
}

[[nodiscard]] crypto::Hash256 msg_id_v2_checked_(const randio::module115::BridgeMessageV2& msg, const randio::module115::DecodeOptions& opt, bool& ok) {
    ok = false;
    const auto enc = randio::module115::encode_message_v2(msg, opt);
    if (!enc) {
        return crypto::Hash256{};
    }
    std::vector<std::uint8_t> buf;
    static constexpr std::string_view kDomain = "randium:bridge115:msgid:v2";
    buf.reserve(kDomain.size() + enc->size());
    buf.insert(buf.end(), kDomain.begin(), kDomain.end());
    buf.insert(buf.end(), enc->begin(), enc->end());
    ok = true;
    return crypto::sha256(std::span<const std::uint8_t>(buf.data(), buf.size()));
}

}

VerifyResult verify_message(const GlobalState& st,
                           const ChainDB& db,
                           const VerifyOptions& opt,
                           const randio::module115::BridgeMessageV2& msg,
                           const std::span<const std::uint8_t> proof_bytes) {
    randio::module115::DecodeOptions mopt;
    if (opt.max_message_bytes > 0) {
        mopt.max_total_bytes = static_cast<std::size_t>(opt.max_message_bytes);
        if (mopt.max_total_bytes != opt.max_message_bytes) {
            return vr_err_(VerifyError::Overflow, crypto::Hash256{});
        }
    }

    bool msg_ok = false;
    const auto msg_id = msg_id_v2_checked_(msg, mopt, msg_ok);
    if (!msg_ok) {
        return vr_err_(VerifyError::BadFormat, crypto::Hash256{});
    }

    if (st.bridge_is_seen(msg_id)) {
        return vr_err_(VerifyError::Replay, msg_id);
    }

    const auto pv_u16 = st.protocol_version();
    const auto pv = static_cast<std::uint32_t>(pv_u16);
    if (opt.min_protocol_version > 0 && pv < opt.min_protocol_version) {
        return vr_err_(VerifyError::BadVersion, msg_id);
    }
    if (opt.max_protocol_version > 0 && pv > opt.max_protocol_version) {
        return vr_err_(VerifyError::BadVersion, msg_id);
    }

    if (opt.max_proof_bytes > 0) {
        if (proof_bytes.size() > opt.max_proof_bytes) {
            return vr_err_(VerifyError::BadFormat, msg_id);
        }
    }

    ValidatorStore keys;
    StakingLedger staking(StakingLedger::Options{});
    if (!st.load_validator_set(keys, staking)) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }
    const auto cp_raw = st.latest_signed_checkpoint_bytes();
    if (!cp_raw) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }
    const auto cp = randio::consensus::decode_signed_checkpoint(std::span<const std::uint8_t>(cp_raw->data(), cp_raw->size()));
    if (!cp) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }
    if (randio::consensus::verify_signed_checkpoint(*cp, keys, staking) != randio::consensus::VerifyStatus::Ok) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }

    const auto cp_pv_u32 = static_cast<std::uint32_t>(cp->header.protocol_version);
    if (opt.min_protocol_version > 0 && cp_pv_u32 < opt.min_protocol_version) {
        return vr_err_(VerifyError::BadVersion, msg_id);
    }
    if (opt.max_protocol_version > 0 && cp_pv_u32 > opt.max_protocol_version) {
        return vr_err_(VerifyError::BadVersion, msg_id);
    }
    if (cp_pv_u32 < pv) {
        return vr_err_(VerifyError::BadVersion, msg_id);
    }

    module80::TxInclusionProof tp;
    std::size_t consumed = 0;
    module80::DecodeOptions popt;
    if (opt.max_proof_bytes > 0) {
        popt.max_total_bytes = static_cast<std::size_t>(opt.max_proof_bytes);
        if (popt.max_total_bytes != opt.max_proof_bytes) {
            return vr_err_(VerifyError::Overflow, msg_id);
        }
    }

    const auto dst = module80::decode_tx_inclusion_proof(proof_bytes, tp, consumed, popt);
    if (dst != module80::DecodeStatus::Ok || consumed != proof_bytes.size()) {
        return vr_err_(VerifyError::BadFormat, msg_id);
    }

    const auto tip = db.tip();
    if (!tip) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }
    if (tp.header.height > tip->height) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }

    if (tp.header.height < cp->header.height) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }

    const auto hdr_at_h = db.header_by_height(tp.header.height);
    if (!hdr_at_h) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }
    if (randio::block_hash(*hdr_at_h) != randio::block_hash(tp.header)) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }

    const auto tx_expected = randio::crypto::to_hex(msg_id);
    const auto tx_payload = std::string_view(reinterpret_cast<const char*>(tp.tx.payload.data()), tp.tx.payload.size());
    if (tx_payload != tx_expected) {
        return vr_err_(VerifyError::PayloadMismatch, msg_id);
    }

    module83::VerifierOptions lcopt;
    lcopt.proof_decode = popt;
    module83::LightClientVerifier v(lcopt);

    const module82::Checkpoint chk{cp->header.height, cp->header.block_hash};
    v.set_checkpoints(std::vector<module82::Checkpoint>{chk});

    const auto headers = load_headers_upto_(db, tp.header.height);
    if (headers.size() != static_cast<std::size_t>(tp.header.height + 1)) {
        return vr_err_(VerifyError::BadCheckpoint, msg_id);
    }

    for (const auto& h : headers) {
        const auto ast = v.add_header(h);
        if (ast != module82::AddStatus::Ok && ast != module82::AddStatus::Duplicate) {
            return vr_err_(VerifyError::BadCheckpoint, msg_id);
        }
    }

    const auto vst = v.verify_tx_inclusion_proof(tp);
    if (vst != module83::VerifyStatus::Ok) {
        return vr_err_(VerifyError::BadProof, msg_id);
    }

    VerifyResult ok;
    ok.err = VerifyError::Ok;
    ok.msg_id = msg_id;
    return ok;
}

}
