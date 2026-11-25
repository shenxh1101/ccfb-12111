// Golden conformance: every golden/samples/*.fw must parse to exactly the
// JSON in golden/expected/*.json. Comparison is a recursive deep-equal that
// reports the first differing field path, so a format drift is localized
// immediately instead of showing two giant JSON blobs.
//
// Run: node --test test/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseBytes } from '../src/parser.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const samplesDir = join(root, 'golden', 'samples');
const expectedDir = join(root, 'golden', 'expected');

function diff(path, actual, expected) {
  const aType = Array.isArray(actual) ? 'array' : actual === null ? 'null' : typeof actual;
  const eType = Array.isArray(expected) ? 'array' : expected === null ? 'null' : typeof expected;
  if (aType !== eType) {
    return `${path}: type ${aType} != ${eType} (actual=${JSON.stringify(actual)})`;
  }
  if (aType === 'array') {
    if (actual.length !== expected.length) {
      return `${path}: array length ${actual.length} != ${expected.length}`;
    }
    for (let i = 0; i < actual.length; i++) {
      const d = diff(`${path}[${i}]`, actual[i], expected[i]);
      if (d) return d;
    }
    return null;
  }
  if (aType === 'object') {
    const aKeys = Object.keys(actual).sort();
    const eKeys = Object.keys(expected).sort();
    if (JSON.stringify(aKeys) !== JSON.stringify(eKeys)) {
      return `${path}: keys ${JSON.stringify(aKeys)} != ${JSON.stringify(eKeys)}`;
    }
    for (const key of eKeys) {
      const d = diff(`${path}.${key}`, actual[key], expected[key]);
      if (d) return d;
    }
    return null;
  }
  if (actual !== expected) {
    return `${path}: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`;
  }
  return null;
}

const sampleFiles = readdirSync(samplesDir).filter((f) => f.endsWith('.fw')).sort();

test('golden corpus covers all 16 samples', () => {
  assert.equal(sampleFiles.length, 16);
});

for (const fw of sampleFiles) {
  const id = fw.replace(/\.fw$/, '');
  test(`golden match: ${id}`, async () => {
    const bytes = new Uint8Array(readFileSync(join(samplesDir, fw)));
    const expected = JSON.parse(
      readFileSync(join(expectedDir, `${id}.json`), 'utf8'));
    const actual = await parseBytes(bytes, fw);
    const mismatch = diff('$', actual, expected);
    assert.equal(mismatch, null, mismatch ?? 'mismatch found');
  });
}

test('truncated-header sample never throws and yields F001', async () => {
  const bytes = new Uint8Array(readFileSync(join(samplesDir, '03-truncated-header.fw')));
  const r = await parseBytes(bytes, '03-truncated-header.fw');
  assert.equal(r.header, null);
  assert.deepEqual(r.findings.map((f) => f.ruleId), ['F001']);
});

test('zero-byte input is handled gracefully', async () => {
  const r = await parseBytes(new Uint8Array(0), 'empty.fw');
  assert.deepEqual(r.findings.map((f) => f.ruleId), ['F001']);
  assert.equal(r.partitions.length, 0);
});
