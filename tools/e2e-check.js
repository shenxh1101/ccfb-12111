// End-to-end check driven through Chrome DevTools Protocol (no npm deps).
// Launches headless Chrome, loads the workbench, clicks golden samples to
// exercise the real Worker + ChunkedReader + parser path inside a browser,
// and asserts the rendered views match the golden expected JSON.
//
// Run: node tools/e2e-check.js [port]

import { spawn } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const port = process.argv[2] || 8123;
const chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const profile = mkdtempSync(join(tmpdir(), 'fwai-cdp-'));

const proc = spawn(chrome, [
  '--headless=new', '--disable-gpu', '--no-first-run',
  `--user-data-dir=${profile}`,
  '--remote-debugging-port=9333',
  `http://localhost:${port}/web/index.html`,
], { stdio: ['ignore', 'pipe', 'pipe'] });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getWsUrl() {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch('http://localhost:9333/json/new?about:blank', { method: 'PUT' });
      if (r.ok) return (await r.json()).webSocketDebuggerUrl;
    } catch { /* retry */ }
    await sleep(250);
  }
  throw new Error('Chrome DevTools endpoint unreachable');
}

const wsUrl = await getWsUrl();
const ws = new WebSocket(wsUrl);
await new Promise((r) => (ws.onopen = r));

let msgId = 0;
const pending = new Map();
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m);
    pending.delete(m.id);
  }
};
const send = (method, params = {}) => new Promise((resolve) => {
  const id = ++msgId;
  pending.set(id, resolve);
  ws.send(JSON.stringify({ id, method, params }));
});
const evalJs = async (expression) => {
  const r = await send('Runtime.evaluate', {
    expression, awaitPromise: true, returnByValue: true,
  });
  if (r.result?.exceptionDetails) {
    throw new Error(JSON.stringify(r.result.exceptionDetails));
  }
  return r.result.result.value;
};

// Every evaluated scenario is an isolated IIFE, so define waitFor inside each.
const WAIT_FOR = `
  const waitFor = async (fn, ms = 8000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const v = fn();
      if (v) return v;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error('waitFor timeout');
  };`;

const card = (name) => `[...document.querySelectorAll('[data-golden]')]
    .find((e) => e.dataset.golden === '${name}')`;

await send('Page.enable');
await send('Runtime.enable');
await send('Page.navigate', { url: `http://localhost:${port}/web/index.html` });
await sleep(2500);

const ready = await evalJs(`document.querySelector('#golden-status')?.textContent`);
console.log('page status:', ready);

// Scenario 1: the deliberately truncated sample must parse, not crash.
const clickResult = await evalJs(`(async () => {
  ${WAIT_FOR}
  location.hash = '#/upload';
  await new Promise((r) => setTimeout(r, 200));
  (await waitFor(() => ${card('03-truncated-header.fw')})).click();
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 100));
    if (document.querySelector('#current-file')?.textContent.includes('03-truncated-header')) break;
  }
  location.hash = '#/findings';
  await new Promise((r) => setTimeout(r, 300));
  const findingRows = [...document.querySelectorAll('#page-findings tbody tr')]
    .map((tr) => tr.querySelector('strong')?.textContent);
  location.hash = '#/partitions';
  await new Promise((r) => setTimeout(r, 200));
  const emptyPartitions = document.querySelector('#page-partitions .empty-state')?.textContent || null;
  location.hash = '#/library';
  await new Promise((r) => setTimeout(r, 400));
  const libRows = document.querySelectorAll('#page-library tbody tr').length;
  return { findingRows, emptyPartitions, libRows,
    chip: document.querySelector('#current-file')?.textContent };
})()`);
console.log('truncated sample UI result:', JSON.stringify(clickResult));

// Scenario 2: valid signed sample + report content parity.
const validResult = await evalJs(`(async () => {
  ${WAIT_FOR}
  location.hash = '#/upload';
  await new Promise((r) => setTimeout(r, 200));
  (await waitFor(() => ${card('02-valid-lz-signed.fw')})).click();
  for (let i = 0; i < 80; i++) {
    await new Promise((r) => setTimeout(r, 100));
    const chip = document.querySelector('#current-file')?.textContent || '';
    if (chip.includes('02-valid-lz-signed') && chip.includes('0 命中')) break;
  }
  location.hash = '#/report';
  await new Promise((r) => setTimeout(r, 300));
  const md = document.querySelector('pre.report-preview')?.textContent || '';
  const hasSections = ['文件头', '分区视图', '漏洞与规则命中', '签名段'].every((s) => md.includes(s));
  const digestLine = md.includes('signedDigest');
  location.hash = '#/partitions';
  await new Promise((r) => setTimeout(r, 200));
  const partRows = document.querySelectorAll('#page-partitions tbody tr').length;
  const typeLabels = [...document.querySelectorAll('#page-partitions .pill.accent')]
    .map((e) => e.textContent);
  return { hasSections, digestLine, partRows, typeLabels,
    chip: document.querySelector('#current-file')?.textContent };
})()`);
console.log('valid sample UI result:', JSON.stringify(validResult));

// Scenario 3: tag editing + filtering in the library.
const libResult = await evalJs(`(async () => {
  ${WAIT_FOR}
  location.hash = '#/library';
  await waitFor(() => document.querySelector('[data-tagfor]'));
  const before = document.querySelectorAll('#page-library tbody tr').length;
  const input = document.querySelector('[data-tagfor]');
  input.value = 'nightly,回归';
  input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
  await new Promise((r) => setTimeout(r, 400));
  const tags = [...document.querySelectorAll('#page-library .pill')].map((e) => e.textContent);
  const tagChip = await waitFor(() => [...document.querySelectorAll('[data-tag]')]
    .find((e) => e.dataset.tag === 'nightly'));
  tagChip.click();
  await new Promise((r) => setTimeout(r, 300));
  const filtered = document.querySelectorAll('#page-library tbody tr').length;
  return { before, afterTag: tags, filtered };
})()`);
console.log('library UI result:', JSON.stringify(libResult));

const expected03 = JSON.parse(readFileSync(
  join(root, 'golden/expected/03-truncated-header.json'), 'utf8'));
const expected02 = JSON.parse(readFileSync(
  join(root, 'golden/expected/02-valid-lz-signed.json'), 'utf8'));

const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); };

check(ready?.includes('16'), 'golden manifest with 16 samples rendered');
check(JSON.stringify(clickResult.findingRows)
  === JSON.stringify(expected03.findings.map((f) => f.ruleId)),
  `truncated findings ${JSON.stringify(clickResult.findingRows)} != golden`);
check(clickResult.emptyPartitions !== null, 'truncated sample shows empty partition view');
check(clickResult.libRows >= 1, 'analysis persisted to IndexedDB library');
check(validResult.partRows === expected02.partitions.length,
  `partition row count ${validResult.partRows} != ${expected02.partitions.length}`);
check(JSON.stringify(validResult.typeLabels)
  === JSON.stringify(expected02.partitions.map((p) => p.entryTypeLabel)),
  'partition type labels mismatch');
check(validResult.hasSections, 'markdown report missing sections');
check(validResult.digestLine, 'markdown report missing signedDigest');
check(libResult.afterTag.includes('nightly') && libResult.afterTag.includes('回归'),
  'tag edit did not persist in UI');
check(libResult.filtered >= 1, 'tag filter returned no rows');

// Scenario 4: cancellation of the 12 MB RLE bomb. Either the cancel lands and
// a banner appears, or analysis finishes first — both are crash-free outcomes.
const cancelResult = await evalJs(`(async () => {
  ${WAIT_FOR}
  location.hash = '#/upload';
  await new Promise((r) => setTimeout(r, 200));
  (await waitFor(() => ${card('12-bomb-hardcap.fw')})).click();
  for (let i = 0; i < 5; i++) {
    document.querySelector('#btn-cancel')?.click();
    await new Promise((r) => setTimeout(r, 10));
  }
  for (let i = 0; i < 100; i++) {
    await new Promise((r) => setTimeout(r, 50));
    const banner = document.querySelector('#page-upload .banner')?.textContent || '';
    const chip = document.querySelector('#current-file')?.textContent || '';
    const onUpload = location.hash === '#/upload' || location.hash === '';
    if (onUpload && banner.includes('取消')) {
      return { outcome: 'cancelled-banner', pageAlive: true, banner };
    }
    if (chip.includes('12-bomb-hardcap') && !onUpload) {
      return { outcome: 'completed-fast', pageAlive: true };
    }
  }
  return { outcome: 'timeout', pageAlive: !!document.querySelector('#dropzone') };
})()`);
console.log('cancel UI result:', JSON.stringify(cancelResult));

ws.close();
proc.kill();

check(cancelResult.pageAlive, 'page crashed during cancellation flow');
check(cancelResult.outcome === 'completed-fast'
  || cancelResult.outcome === 'cancelled-banner',
  `unexpected cancellation outcome: ${cancelResult.outcome}`);

if (failures.length) {
  console.error('\nE2E FAILURES:');
  for (const f of failures) console.error(' -', f);
  process.exit(1);
}
console.log('\nAll E2E checks passed.');
