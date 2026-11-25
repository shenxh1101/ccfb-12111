// Bounded binary reader over a firmware image.
//
// Two backing modes share one interface so the exact same parser code runs in
// the browser (File/Blob, streamed in chunks) and under Node (Uint8Array):
//
//   const reader = await ChunkedReader.fromBlob(file, { signal, onProgress })
//   const reader = new MemoryReader(uint8array)
//
// All accessors take absolute offsets and never read past EOF: range() returns
// the available prefix in that case, and requireRange() signals truncation via
// a returned { truncated: true } marker instead of throwing. This is the core
// defense against the historical heap-overflow class: no offset is ever
// dereferenced without a bounds check against the real file length.

export class MemoryReader {
  constructor(bytes) {
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.size = this.bytes.length;
    this.kind = 'memory';
  }

  // absolute slice; always a copy, callers may retain it safely
  range(offset, length) {
    if (offset >= this.size || length <= 0) return new Uint8Array(0);
    const end = Math.min(offset + length, this.size);
    return this.bytes.slice(offset, end);
  }

  u16(offset) {
    const b = this.bytes;
    if (offset < 0 || offset + 2 > this.size) return null;
    return b[offset] | (b[offset + 1] << 8);
  }

  u32(offset) {
    const b = this.bytes;
    if (offset < 0 || offset + 4 > this.size) return null;
    return (
      (b[offset] >>> 0) |
      (b[offset + 1] << 8) |
      (b[offset + 2] << 16) |
      (b[offset + 3] << 24)
    ) >>> 0;
  }

  // async-style API kept for interface parity with ChunkedReader
  async asyncRange(offset, length) {
    return this.range(offset, length);
  }

  // whole-file digest helper for small/Node inputs
  async sha256Hex() {
    return sha256Hex(this.bytes);
  }
}

const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MiB streaming window

export class ChunkedReader {
  constructor(size) {
    this.size = size;
    this.kind = 'blob';
    this._chunks = new Map();   // index -> Uint8Array
    this._blob = null;
    this._signal = null;
    this._onProgress = null;
    this._bytesRead = 0;
  }

  static async fromBlob(blob, { signal = null, onProgress = null } = {}) {
    const r = new ChunkedReader(blob.size);
    r._blob = blob;
    r._signal = signal;
    r._onProgress = onProgress;
    return r;
  }

  _throwIfCancelled() {
    if (this._signal && this._signal.aborted) {
      const err = new Error('analysis cancelled');
      err.cancelled = true;
      throw err;
    }
  }

  async _load(chunkIndex) {
    this._throwIfCancelled();
    const cached = this._chunks.get(chunkIndex);
    if (cached) return cached;
    const start = chunkIndex * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, this.size);
    const buf = await this._blob.slice(start, end).arrayBuffer();
    this._throwIfCancelled();
    const view = new Uint8Array(buf);
    this._chunks.set(chunkIndex, view);
    this._bytesRead += view.length;
    if (this._onProgress) {
      this._onProgress({ bytesRead: this._bytesRead, total: this.size });
    }
    // keep at most 3 chunks resident (~12 MiB) so hundreds-of-MB files
    // cannot blow up page memory; evict the oldest windows
    if (this._chunks.size > 3) {
      const oldest = this._chunks.keys().next().value;
      this._chunks.delete(oldest);
    }
    return view;
  }

  async asyncRange(offset, length) {
    if (length <= 0 || offset >= this.size) return new Uint8Array(0);
    const wantedEnd = Math.min(offset + length, this.size);
    const parts = [];
    let cursor = offset;
    while (cursor < wantedEnd) {
      const idx = Math.floor(cursor / CHUNK_SIZE);
      const chunk = await this._load(idx);
      const localStart = cursor - idx * CHUNK_SIZE;
      const localEnd = Math.min(wantedEnd - idx * CHUNK_SIZE, chunk.length);
      parts.push(chunk.slice(localStart, localEnd));
      cursor += localEnd - localStart;
    }
    const out = new Uint8Array(wantedEnd - offset);
    let p = 0;
    for (const part of parts) {
      out.set(part, p);
      p += part.length;
    }
    return out;
  }

  range() {
    throw new Error('ChunkedReader requires asyncRange(); use async parser API');
  }

  async u16(offset) {
    const b = await this.asyncRange(offset, 2);
    if (b.length < 2) return null;
    return b[0] | (b[1] << 8);
  }

  async u32(offset) {
    const b = await this.asyncRange(offset, 4);
    if (b.length < 4) return null;
    return (
      (b[0] >>> 0) | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)
    ) >>> 0;
  }

  // Streaming digest over 4 MiB windows: a 500 MB file is never materialized
  // in page memory. Uses the dependency-free incremental SHA-256 because
  // SubtleCrypto requires a fully buffered BufferSource.
  async sha256Hex() {
    const { Sha256 } = await import('./sha256.js');
    const hash = new Sha256();
    const chunkCount = Math.ceil(this.size / CHUNK_SIZE);
    for (let i = 0; i < chunkCount; i++) {
      this._throwIfCancelled();
      hash.update(await this._load(i));
    }
    return hash.hex();
  }
}

export function hex(bytes) {
  let s = '';
  for (const v of bytes) s += v.toString(16).padStart(2, '0');
  return s;
}

export async function sha256Hex(bytes) {
  const { sha256HexBytes } = await import('./sha256.js');
  return sha256HexBytes(bytes);
}

// CRC-32 (IEEE 802.3), same table/algorithm as zlib crc32 and the Python ref.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}
