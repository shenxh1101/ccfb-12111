// Web Worker: runs the whole firmware parse off the UI thread.
//
// Protocol (main -> worker):
//   { type: 'analyze', file: File }            start analysis
//   { type: 'cancel' }                         cooperative cancel
//
// Protocol (worker -> main):
//   { type: 'progress', phase, percent, detail }
//   { type: 'done', result, cancelled }
//
// The worker never imports DOM APIs; parser + reader are the same ESM modules
// exercised by node --test, so what passes golden conformance is exactly what
// the browser runs.

import { ChunkedReader } from '../src/reader.js';
import { parseWithCancel } from '../src/parser.js';

let currentController = null;

self.onmessage = async (ev) => {
  const msg = ev.data;
  if (msg.type === 'cancel') {
    currentController?.abort();
    return;
  }
  if (msg.type !== 'analyze') return;

  const { file } = msg;
  currentController = new AbortController();
  try {
    const reader = await ChunkedReader.fromBlob(file, {
      signal: currentController.signal,
    });
    const out = await parseWithCancel(reader, file.name, {
      signal: currentController.signal,
      onProgress: (p) => {
        self.postMessage({ type: 'progress', ...p });
      },
    });
    self.postMessage({
      type: 'done',
      result: out.result,
      cancelled: out.cancelled,
      error: out.error ?? null,
    });
  } catch (err) {
    self.postMessage({
      type: 'done',
      result: null,
      cancelled: false,
      error: err?.message ?? String(err),
    });
  } finally {
    currentController = null;
  }
};
