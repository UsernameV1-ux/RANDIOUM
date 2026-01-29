(function (global) {
  const bytesEq = (a, b) => {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; ++i) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  };

  const hexToBytes = (hex) => {
    let s = String(hex || '').trim();
    if (s.startsWith('0x') || s.startsWith('0X')) s = s.slice(2);
    if (s.length === 0) return new Uint8Array(0);
    if ((s.length & 1) !== 0) throw new Error('bad hex length');
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; ++i) {
      const byte = parseInt(s.slice(i * 2, i * 2 + 2), 16);
      if (!Number.isFinite(byte)) throw new Error('bad hex');
      out[i] = byte;
    }
    return out;
  };

  const readU32LE = (b, off) =>
    (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;

  const readU64LE = (b, off) => {
    let v = 0n;
    for (let i = 0; i < 8; ++i) {
      v |= BigInt(b[off + i]) << (8n * BigInt(i));
    }
    return v;
  };

  const decodeVarU64Canonical = (b, off) => {
    if (off >= b.length) throw new Error('varint empty');
    let v = 0n;
    let shift = 0n;
    let consumed = 0;
    for (let i = 0; i < 10; ++i) {
      if (off + i >= b.length) throw new Error('varint unterminated');
      const byte = b[off + i];
      const chunk = BigInt(byte & 0x7f);
      if (shift >= 64n) throw new Error('varint too long');
      if (shift === 63n && chunk > 1n) throw new Error('varint overflow');
      v |= chunk << shift;
      consumed = i + 1;
      if ((byte & 0x80) === 0) {
        if (v === 0n) {
          if (consumed !== 1) throw new Error('varint noncanonical');
        } else {
          const minShift = BigInt(consumed - 1) * 7n;
          if (minShift >= 64n) throw new Error('varint overflow');
          const minV = minShift === 63n ? (1n << 63n) : (1n << minShift);
          if (v < minV) throw new Error('varint noncanonical');
        }
        return { value: v, consumed };
      }
      shift += 7n;
    }
    throw new Error('varint too long');
  };

  const merkleDepth = (leafCount) => {
    if (leafCount <= 1n) return 0;
    let d = 0;
    let n = 1n;
    while (n < leafCount) {
      n <<= 1n;
      d += 1;
    }
    return d;
  };

  const sha256 = async (bytes) => {
    const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const digest = await crypto.subtle.digest('SHA-256', buf);
    return new Uint8Array(digest);
  };

  const merkleParent = async (left32, right32) => {
    const buf = new Uint8Array(64);
    buf.set(left32, 0);
    buf.set(right32, 32);
    return sha256(buf);
  };

  const computeMerkleRoot = async (leafHash32, proof) => {
    if (proof.leafCount === 0n) return null;
    if (proof.leafIndex >= proof.leafCount) return null;
    if (proof.siblings.length !== merkleDepth(proof.leafCount)) return null;

    let cur = leafHash32;
    let idx = proof.leafIndex;
    for (let depth = 0; depth < proof.siblings.length; ++depth) {
      const sib = proof.siblings[depth];
      if ((idx & 1n) === 0n) {
        cur = await merkleParent(cur, sib);
      } else {
        cur = await merkleParent(sib, cur);
      }
      idx >>= 1n;
    }
    return cur;
  };

  const decodeHeader = (b, off) => {
    const size = 4 + 8 + 32 + 32 + 8 + 8;
    if (off + size > b.length) throw new Error('header too short');

    const version = readU32LE(b, off);
    const height = readU64LE(b, off + 4);
    const prev = b.slice(off + 12, off + 44);
    const merkleRoot = b.slice(off + 44, off + 76);
    const ts = readU64LE(b, off + 76);
    const nonce = readU64LE(b, off + 84);

    return {
      header: { version, height, prev, merkleRoot, ts, nonce },
      consumed: size
    };
  };

  const decodeTx = (b, off, tlen) => {
    if (off + tlen > b.length) throw new Error('tx too short');
    if (tlen < 24) throw new Error('tx too short');
    const ver = readU32LE(b, off);
    const nonce = readU64LE(b, off + 4);
    const fee = readU64LE(b, off + 12);
    const plen = readU32LE(b, off + 20);
    if (24 + plen !== tlen) throw new Error('tx length mismatch');
    const payload = b.slice(off + 24, off + 24 + plen);
    const raw = b.slice(off, off + tlen);
    return { tx: { ver, nonce, fee, payload, raw }, consumed: tlen };
  };

  const decodeMerkleProof = (b, off) => {
    const a = decodeVarU64Canonical(b, off);
    off += a.consumed;
    const c = decodeVarU64Canonical(b, off);
    off += c.consumed;
    const s = decodeVarU64Canonical(b, off);
    off += s.consumed;

    const leafIndex = a.value;
    const leafCount = c.value;
    const sibCount = s.value;

    if (sibCount > 1000000n) throw new Error('too many siblings');

    const siblings = [];
    for (let i = 0n; i < sibCount; ++i) {
      if (off + 32 > b.length) throw new Error('merkle proof too short');
      siblings.push(b.slice(off, off + 32));
      off += 32;
    }

    return { proof: { leafIndex, leafCount, siblings }, consumed: off };
  };

  const verifyTxInclusionProofBytes = async (bytes) => {
    const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (b.length === 0) return { ok: false, error: 'empty' };

    const magic = [0x52, 0x50, 0x52, 0x46];
    if (b.length < 6) return { ok: false, error: 'too short' };
    for (let i = 0; i < 4; ++i) {
      if (b[i] !== magic[i]) return { ok: false, error: 'bad magic' };
    }
    if (b[4] !== 1) return { ok: false, error: 'bad version' };
    if (b[5] !== 1) return { ok: false, error: 'bad kind' };

    let off = 6;

    const dh = decodeHeader(b, off);
    const header = dh.header;
    off += dh.consumed;

    if (off + 4 > b.length) return { ok: false, error: 'tx len too short' };
    const tlen = readU32LE(b, off);
    off += 4;

    const dt = decodeTx(b, off, tlen);
    const tx = dt.tx;
    off += dt.consumed;

    const mp = decodeMerkleProof(b, off);
    const proof = mp.proof;
    off = mp.consumed;

    if (off !== b.length) return { ok: false, error: 'noncanonical trailing bytes' };

    const leafHash = await sha256(tx.raw);
    const root = await computeMerkleRoot(leafHash, proof);
    if (!root) return { ok: false, error: 'invalid merkle proof' };

    const ok = bytesEq(root, header.merkleRoot);
    return {
      ok,
      error: ok ? null : 'root mismatch',
      details: {
        headerHeight: header.height.toString(),
        txVersion: tx.ver,
        leafIndex: proof.leafIndex.toString(),
        leafCount: proof.leafCount.toString()
      }
    };
  };

  const verifyTxInclusionProofHex = async (hex) => {
    const bytes = hexToBytes(hex);
    return verifyTxInclusionProofBytes(bytes);
  };

  global.RandProof = {
    verifyTxInclusionProofHex,
    verifyTxInclusionProofBytes
  };
})(typeof window !== 'undefined' ? window : globalThis);
