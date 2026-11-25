// FWAI firmware audit parser — browser/Node shared implementation.
//
// Deterministic four-stage pipeline, mirroring reference/fwai_format.py:
//   1. header   2. partition table   3. per-segment checks   4. global checks
//
// The parser is fully async so ChunkedReader can stream Blob data without
// blocking the UI thread (it runs inside a Web Worker in the workbench).
// Cancellation is cooperative: reader access checks the AbortSignal between
// every stage and between entries; already-produced findings are returned to
// the caller by parseWithCancel() when an abort is observed.

import {
  RULES, HEADER_SIZE, ENTRY_SIZE, MAX_PARTITIONS,
  BOMB_RATIO, BOMB_RAW_GATE, SIG_MIN_LEN, SIG_MAX_LEN, SIG_PUBLIC_LEN,
  TYPE_RAW, TYPE_LZ, TYPE_SIGNATURE, TYPE_LABELS,
  FLAG_ENCRYPTED,
} from './rules.js';
import { MemoryReader, crc32, hex, sha256Hex } from './reader.js';
import { lzDecode } from './lz.js';

class FindingCollector {
  constructor() {
    this.findings = [];
  }

  add(ruleId, offset, entryIndex) {
    const [severity, message] = RULES[ruleId];
    this.findings.push({ ruleId, severity, offset, entryIndex, message });
  }
}

function finalize(result, collector) {
  collector.findings.sort(
    (a, b) => a.offset - b.offset
      || a.ruleId.localeCompare(b.ruleId)
      || a.entryIndex - b.entryIndex,
  );
  result.findings = collector.findings;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of collector.findings) counts[f.severity]++;
  result.summary = {
    findingCounts: counts,
    totalFindings: collector.findings.length,
    partitionsTotal: result.partitions.length,
    partitionsTruncated: result.partitions.filter((p) => p.truncated).length,
    partitionsUnparseable: result.partitions.filter((p) => p.unparseable).length,
  };
  return result;
}

function emptyResult(fileName, fileSize, sha256) {
  return {
    schemaVersion: 1,
    fileName,
    fileSize,
    sha256,
    header: null,
    partitions: [],
    findings: [],
    signature: null,
    summary: {},
  };
}

function partitionRow(e, crcValid, truncated, unparseable, detail) {
  return {
    entryIndex: e.entryIndex,
    name: e.name,
    entryType: e.entryType,
    entryTypeLabel: TYPE_LABELS[e.entryType] ?? 'UNKNOWN',
    entryOffset: e.entryOffset,
    storedSize: e.storedSize,
    rawSize: e.rawSize,
    entryCrc32: e.entryCrc32,
    crcValid,
    truncated,
    unparseable,
    detail,
  };
}

/**
 * Parse a firmware image.
 * @param {MemoryReader|ChunkedReader} reader
 * @param {string} fileName
 * @param {object} [opts]
 * @param {AbortSignal} [opts.signal]
 * @param {(p:{phase:string,percent:number,detail?:string})=>void} [opts.onProgress]
 */
export async function parseFirmware(reader, fileName, opts = {}) {
  const { signal = null, onProgress = null } = opts;
  const progress = (phase, percent, detail) =>
    onProgress?.({ phase, percent, detail });

  const size = reader.size;
  const collector = new FindingCollector();
  const sha256 = await reader.sha256Hex();
  const result = emptyResult(fileName, size, sha256);

  const readU16 = (off) => reader.kind === 'memory'
    ? Promise.resolve(reader.u16(off)) : reader.u16(off);
  const readU32 = (off) => reader.kind === 'memory'
    ? Promise.resolve(reader.u32(off)) : reader.u32(off);
  const readRange = (off, len) => reader.asyncRange(off, len);

  // On abort we keep everything produced so far: finalize the partial result
  // and attach it to the cancellation error, where parseWithCancel picks it up.
  const check = () => {
    if (signal?.aborted) {
      const err = new Error('analysis cancelled');
      err.cancelled = true;
      err.partialResult = finalize(result, collector);
      throw err;
    }
  };
  check.signal = signal;

  // ---- stage 1: header ---------------------------------------------------- //
  progress('header', 2, 'reading header');
  check();
  if (size < HEADER_SIZE) {
    collector.add('F001', 0, -1);
    return finalize(result, collector);
  }
  const headBytes = await readRange(0, HEADER_SIZE);
  const magicOk = headBytes[0] === 0x46 && headBytes[1] === 0x57
    && headBytes[2] === 0x41 && headBytes[3] === 0x49;
  if (!magicOk) {
    collector.add('F003', 0, -1);
    return finalize(result, collector);
  }

  const header = {
    magic: 'FWAI',
    headerVersion: await readU16(4),
    headerSize: await readU16(6),
    fileSize: await readU32(8),
    partitionTableOffset: await readU32(12),
    partitionCount: await readU16(16),
    flags: await readU16(18),
    headerCrc32: await readU32(20),
    reserved: hex(headBytes.slice(24, 32)),
  };
  result.header = header;

  // CRC field itself sits inside [0,28): verify with the field zeroed.
  const headForCrc = headBytes.slice(0, 28);
  headForCrc[20] = headForCrc[21] = headForCrc[22] = headForCrc[23] = 0;
  if (crc32(headForCrc) !== header.headerCrc32) collector.add('F002', 20, -1);
  if (headBytes.slice(24, 32).some((x) => x !== 0)) collector.add('F016', 24, -1);
  if (header.flags & FLAG_ENCRYPTED) collector.add('F019', 18, -1);
  if (header.flags & ~0x0003) collector.add('F016', 18, -1);
  if (header.fileSize !== size) collector.add('F020', 8, -1);

  const tableOffset = header.partitionTableOffset;
  const count = header.partitionCount;
  const tableEnd = tableOffset + ENTRY_SIZE * count;
  const tableUnreadable = count > MAX_PARTITIONS
    || tableEnd > size || tableEnd > 0xffffffff || tableOffset > size;
  if (tableUnreadable) {
    collector.add('F004', count > MAX_PARTITIONS ? 16 : 12, -1);
  }

  // ---- stage 2: partition table ------------------------------------------ //
  progress('table', 10, `parsing ${count} table entries`);
  let readable = 0;
  if (!tableUnreadable) {
    readable = count;
  } else if (count <= MAX_PARTITIONS && tableOffset <= size) {
    readable = Math.floor((size - tableOffset) / ENTRY_SIZE);
  }
  const rawEntries = [];
  for (let idx = 0; idx < readable; idx++) {
    check();
    const bp = tableOffset + idx * ENTRY_SIZE;
    const tb = await readRange(bp, ENTRY_SIZE);
    if (tb[17] !== 0) collector.add('F016', bp + 17, idx);
    if (tb[34] !== 0 || tb[35] !== 0) collector.add('F016', bp + 34, idx);
    let nameEnd = 0;
    while (nameEnd < 16 && tb[nameEnd] !== 0) nameEnd++;
    let name = '';
    for (let k = 0; k < nameEnd; k++) name += String.fromCharCode(tb[k]);
    rawEntries.push({
      entryIndex: idx,
      name,
      entryType: tb[16],
      entryOffset: u32From(tb, 18),
      storedSize: u32From(tb, 22),
      rawSize: u32From(tb, 26),
      entryCrc32: u32From(tb, 30),
      tableAbsOffset: bp,
    });
  }

  // ---- stage 3: per-segment checks --------------------------------------- //
  let sigSeen = 0;
  for (let i = 0; i < rawEntries.length; i++) {
    check();
    const e = rawEntries[i];
    progress('segments', 15 + Math.round((i / Math.max(rawEntries.length, 1)) * 65),
      `segment ${i + 1}/${rawEntries.length}: ${e.name}`);
    const start = e.entryOffset;
    const stored = e.storedSize;
    const end = start + stored;
    const unparseable = start > size || end > 0xffffffff;
    let truncated = false;
    if (!unparseable && end > size) {
      truncated = true;
      collector.add('F005', start, e.entryIndex);
    }
    if (unparseable) {
      collector.add('F005', start, e.entryIndex);
      result.partitions.push(
        partitionRow(e, null, false, true, null));
      continue;
    }

    const availEnd = Math.min(end, size);
    const avail = await readRange(start, availEnd - start);
    const crcValid = crc32(avail) === e.entryCrc32;
    if (!crcValid) collector.add('F013', start, e.entryIndex);

    let detail = null;
    if (e.entryType === TYPE_RAW) {
      if (e.rawSize !== stored) collector.add('F010', start, e.entryIndex);
      detail = { raw: { bytes: stored } };
    } else if (e.entryType === TYPE_LZ) {
      detail = await auditLz(e, avail, collector, e.entryIndex, check);
    } else if (e.entryType === TYPE_SIGNATURE) {
      detail = auditSignature(e, avail, collector, e.entryIndex);
      sigSeen++;
      if (sigSeen >= 2) collector.add('F017', start, e.entryIndex);
    } else {
      collector.add('F011', e.tableAbsOffset + 16, e.entryIndex);
    }
    result.partitions.push(partitionRow(e, crcValid, truncated, false, detail));
  }

  // ---- stage 4: global checks -------------------------------------------- //
  progress('global', 88, 'overlap and signature checks');
  check();
  const unparseableIdx = new Set(
    result.partitions.filter((p) => p.unparseable).map((p) => p.entryIndex));
  const intervals = rawEntries
    .filter((e) => e.entryOffset <= size
      && e.entryOffset + e.storedSize <= 0xffffffff
      && !unparseableIdx.has(e.entryIndex))
    .map((e) => [e.entryIndex, e.entryOffset, e.entryOffset + e.storedSize]);
  for (let k = 0; k < intervals.length; k++) {
    const [iIdx, iStart, iEnd] = intervals[k];
    for (let j = k + 1; j < intervals.length; j++) {
      const [jIdx, jStart, jEnd] = intervals[j];
      if (iStart < jEnd && jStart < iEnd) collector.add('F012', jStart, jIdx);
    }
  }

  result.signature = await buildSignatureSummary(
    rawEntries, reader, result, readRange, readU16);
  progress('done', 100, 'complete');
  return finalize(result, collector);
}

async function auditLz(e, avail, collector, idx, check) {
  const rawSize = e.rawSize;
  if (rawSize > BOMB_RAW_GATE
      && Math.floor(rawSize / Math.max(e.storedSize, 1)) > BOMB_RATIO) {
    collector.add('F014', e.entryOffset, idx);
  }
  let dec;
  try {
    dec = await lzDecode(avail, rawSize, () => Boolean(check.signal?.aborted));
  } catch (err) {
    if (err?.cancelled) check();   // unified cancellation exit (carries partial result)
    throw err;
  }
  if (dec.error === 'F014' || dec.error === 'F007' || dec.error === 'F006') {
    collector.add(dec.error, e.entryOffset, idx);
  }
  if (dec.error === null && dec.consumed < avail.length) {
    collector.add('F010', e.entryOffset, idx);
  }
  return {
    lz: {
      controlBytes: dec.controlBytes,
      literalTokens: dec.literalTokens,
      matchTokens: dec.matchTokens,
      consumed: dec.consumed,
      decompressedSize: dec.output.length,
    },
  };
}

function auditSignature(e, avail, collector, idx) {
  const start = e.entryOffset;
  let algorithm = null;
  let sigLength = null;
  let publicData = null;
  if (avail.length >= 4) {
    algorithm = avail[0] | (avail[1] << 8);
    sigLength = avail[2] | (avail[3] << 8);
    if (sigLength < SIG_MIN_LEN) collector.add('F015', start + 2, idx);
    if (sigLength > SIG_MAX_LEN) collector.add('F009', start + 2, idx);
    if (algorithm !== 1) collector.add('F018', start, idx);
    if (avail.length >= 4 + sigLength + SIG_PUBLIC_LEN) {
      publicData = hex(avail.slice(4 + sigLength, 4 + sigLength + SIG_PUBLIC_LEN));
    } else {
      collector.add('F008', start, idx);
    }
  } else {
    collector.add('F008', start, idx);
  }
  return { signature: { algorithm, sigLength, publicData } };
}

async function buildSignatureSummary(rawEntries, reader, result, readRange, readU16) {
  const sigEntries = rawEntries.filter((e) => e.entryType === TYPE_SIGNATURE);
  if (sigEntries.length === 0) return null;
  const e = sigEntries[0];
  const start = e.entryOffset;
  const stored = e.storedSize;
  if (start > reader.size || start + stored > 0xffffffff) return null;
  const avail = await readRange(start, Math.min(stored, reader.size - start));
  const row = result.partitions.find((p) => p.entryIndex === e.entryIndex);
  const malformed = result.findings.some(
    (f) => f.ruleId === 'F008' && f.entryIndex === e.entryIndex);
  const truncated = row?.truncated ?? false;
  const algorithm = avail.length >= 2 ? avail[0] | (avail[1] << 8) : null;
  const sigLength = avail.length >= 4 ? avail[2] | (avail[3] << 8) : null;
  let publicData = null;
  let signedDigest = null;
  if (sigLength !== null && avail.length >= 4 + sigLength + SIG_PUBLIC_LEN) {
    publicData = hex(avail.slice(4 + sigLength, 4 + sigLength + SIG_PUBLIC_LEN));
  }
  if (!malformed && !truncated && publicData !== null) {
    signedDigest = await computeSignedDigest(rawEntries, reader, result, e, readRange);
  }
  return {
    present: true,
    entryIndex: e.entryIndex,
    algorithm,
    sigLength,
    publicData,
    signedDigest,
  };
}

async function computeSignedDigest(rawEntries, reader, result, sigEntry, readRange) {
  const { Sha256 } = await import('./sha256.js');
  const hash = new Sha256();
  hash.update(await readRange(0, HEADER_SIZE));
  const tableOff = result.header.partitionTableOffset;
  const count = result.header.partitionCount;
  hash.update(await readRange(tableOff, ENTRY_SIZE * count));
  const rows = new Map(result.partitions.map((p) => [p.entryIndex, p]));
  for (const e of rawEntries) {
    if (e.entryIndex === sigEntry.entryIndex) continue;
    const row = rows.get(e.entryIndex);
    if (!row || row.truncated || row.unparseable) return null;
    hash.update(await readRange(e.entryOffset, e.storedSize));
  }
  return hash.hex();
}

function u32From(b, off) {
  return ((b[off] >>> 0)
    | (b[off + 1] << 8)
    | (b[off + 2] << 16)
    | (b[off + 3] << 24)) >>> 0;
}

/** Convenience wrapper for small in-memory bytes (Node tests, small files). */
export async function parseBytes(bytes, fileName, opts = {}) {
  return parseFirmware(new MemoryReader(bytes), fileName, opts);
}

/**
 * Cancel-aware wrapper: when the AbortSignal fires, the partial result built
 * so far is returned (findings already emitted stay visible) instead of
 * propagating the abort. Other errors still throw.
 */
export async function parseWithCancel(reader, fileName, opts = {}) {
  try {
    const result = await parseFirmware(reader, fileName, opts);
    return { result, cancelled: false };
  } catch (err) {
    if (err?.cancelled) {
      return {
        result: err.partialResult ?? null,
        cancelled: true,
        error: err.message,
      };
    }
    throw err;
  }
}

export { sha256Hex };
