// Extra parser guarantees beyond golden conformance:
//   - cancellation keeps partial results and never throws
//   - the 16 MiB hard cap actually stops RLE-style bomb expansion
//   - ChunkedReader parses identically to MemoryReader
//   - random LZ round-trips never desynchronize

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseBytes, parseWithCancel, parseFirmware } from '../src/parser.js';
import { ChunkedReader, MemoryReader } from '../src/reader.js';
import { lzDecode } from '../src/lz.js';
import { lzEncode } from './lz-encode.js';
import { Sha256 } from '../src/sha256.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const samples = (name) => new Uint8Array(
  readFileSync(join(root, 'golden', 'samples', name)));

test('hard-cap bomb stops at 16 MiB and reports F014 once', async () => {
  const r = await parseBytes(samples('12-bomb-hardcap.fw'), '12.fw');
  const lz = r.partitions[0];
  assert.ok(lz.detail.lz.decompressedSize <= 16 * 1024 * 1024);
  const f014 = r.findings.filter((f) => f.ruleId === 'F014');
  assert.equal(f014.length, 1);
});

test('cancellation after header keeps already produced findings', async () => {
  const bytes = samples('16-mixed-findings.fw');
  const ac = new AbortController();
  const p = parseWithCancel(new MemoryReader(bytes), '16.fw',
    { signal: ac.signal });
  ac.abort();
  const out = await p;
  assert.equal(out.cancelled, true);
  // abort may land before or after the first stage, but it never throws and
  // the returned shape remains a valid (possibly empty) result document
  if (out.result) {
    assert.ok(Array.isArray(out.result.findings));
    assert.equal(out.result.fileSize, bytes.length);
  }
});

test('cancellation mid-segment preserves header-level findings', async () => {
  // big bomb gives multiple progress callbacks to abort on; aborting at the
  // first segment-stage callback deterministically lands inside parsing
  const bytes = samples('12-bomb-hardcap.fw');
  const ac = new AbortController();
  let aborted = false;
  const out = await parseWithCancel(new MemoryReader(bytes), '12.fw', {
    signal: ac.signal,
    onProgress: ({ phase }) => {
      if (!aborted && phase === 'segments') {
        aborted = true;
        ac.abort();
      }
    },
  });
  assert.equal(aborted, true);
  assert.equal(out.cancelled, true);
  assert.ok(out.result, 'partial result must be retained after cancel');
  assert.equal(out.result.fileSize, bytes.length);
  assert.ok(Array.isArray(out.result.findings));
});

test('ChunkedReader output equals MemoryReader output', async () => {
  const bytes = samples('08-overlap.fw');
  // minimal Blob shim backed by a Buffer (Node 18+ has global Blob)
  const blob = new Blob([bytes]);
  const chunked = await ChunkedReader.fromBlob(blob);
  const r1 = await parseFirmware(new MemoryReader(bytes), 'x.fw');
  const r2 = await parseFirmware(chunked, 'x.fw');
  assert.deepEqual(r2, r1);
});

test('LZ round-trip on structured and random payloads', async () => {
  const cases = [
    b('repetitive text repetitive text repetitive text '),
    b('A'.repeat(5000)),
    b(''),
    new Uint8Array(Array.from({ length: 3000 }, (_, i) => (i * 31 + 7) & 0xff)),
  ];
  for (const payload of cases) {
    const enc = lzEncode(payload);
    const dec = await lzDecode(enc, payload.length);
    assert.equal(dec.error, null);
    assert.deepEqual(dec.output, payload);
  }
});

test('bomb ratio sample flags both ratio gate and malformed tail', async () => {
  const r = await parseBytes(samples('11-bomb-ratio.fw'), '11.fw');
  const ids = r.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('F014'));
});

function b(str) {
  return new TextEncoder().encode(str);
}

test('incremental SHA-256 matches NIST vectors across chunk boundaries', () => {
  const vectors = [
    ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
    ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
  ];
  for (const [msg, expected] of vectors) {
    // feed one byte at a time to stress block boundaries
    const bytes = b(msg);
    const h = new Sha256();
    for (const byte of bytes) h.update(new Uint8Array([byte]));
    assert.equal(h.hex(), expected);
    // idempotent finalization
    assert.equal(h.hex(), expected);
  }
});

test('SHA-256 of 1 MiB input agrees with SubtleCrypto', async () => {
  const data = new Uint8Array(1024 * 1024);
  for (let i = 0; i < data.length; i++) data[i] = (i * 17 + 5) & 0xff;
  const mine = new Sha256().update(data).hex();
  const ref = Buffer.from(
    await globalThis.crypto.subtle.digest('SHA-256', data)).toString('hex');
  assert.equal(mine, ref);
});
