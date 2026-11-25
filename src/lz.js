// LZSS decoder — JS port of reference/fwai_format.py lz_decode(), with
// cooperative yielding for the browser worker.
//
// Safety properties (these are what make the historical heap-overflow class
// impossible here):
//   * every read is bounds-checked against the segment buffer length;
//   * a back-reference is only followed when the output buffer is non-empty,
//     and distance is derived modulo the current output length;
//   * output growth is hard-capped at MAX_OUTPUT (16 MiB);
//   * malformed input yields a rule id, never an exception;
//   * every YIELD_EVERY tokens the decoder awaits a microtask so a several-
//     hundred-MB stream cannot starve the worker's message loop (cancellation
//     and progress events stay responsive).
//
// The returned shape must match the Python LzResult field-for-field after the
// parser wrapper adds decompressedSize.

import { MAX_OUTPUT } from './rules.js';

const YIELD_EVERY = 20000;
const tick = () => new Promise((resolve) => {
  if (typeof queueMicrotask === 'function') queueMicrotask(resolve);
  else Promise.resolve().then(resolve);
});

export async function lzDecode(buf, rawSize, shouldYield = null) {
  const out = new Uint8Array(Math.min(rawSize, MAX_OUTPUT) + 8);
  let outLen = 0;
  let pos = 0;
  const n = buf.length;
  let controlBytes = 0;
  let literalTokens = 0;
  let matchTokens = 0;
  let error = null;
  let sinceYield = 0;

  outer:
  while (outLen < rawSize) {
    if (pos >= n) {
      error = 'F006';
      break;
    }
    const control = buf[pos++];
    controlBytes++;
    for (let bit = 0; bit < 8; bit++) {
      if (outLen >= rawSize) break;
      if (control & (1 << bit)) {
        // literal token
        if (pos >= n) {
          error = 'F006';
          break outer;
        }
        if (outLen < MAX_OUTPUT) out[outLen] = buf[pos];
        outLen++;
        pos++;
        literalTokens++;
      } else {
        // back-reference match token
        if (pos + 2 > n) {
          error = 'F007';
          break outer;
        }
        if (outLen === 0) {
          error = 'F007';
          break outer;
        }
        const raw16 = buf[pos] | (buf[pos + 1] << 8);
        pos += 2;
        const cur = outLen;
        const distance = (raw16 % cur) + 1;
        const length = Math.floor(raw16 / cur) + 3;
        let src = cur - distance;
        for (let k = 0; k < length; k++) {
          if (outLen >= rawSize) break;
          if (outLen >= MAX_OUTPUT) {
            error = 'F014';
            break;
          }
          out[outLen] = out[src];
          outLen++;
          src++;
        }
        matchTokens++;
        if (error) break outer;
      }
      sinceYield++;
      if (sinceYield >= YIELD_EVERY) {
        sinceYield = 0;
        await tick();
        if (shouldYield?.()) {
          // Parser translates this into its structured cancellation error;
          // keep using the same marker so no special-case path is needed.
          const err = new Error('analysis cancelled');
          err.cancelled = true;
          throw err;
        }
      }
    }
    if (error || outLen >= rawSize) break;
  }

  return {
    output: out.slice(0, Math.min(outLen, MAX_OUTPUT)),
    controlBytes,
    literalTokens,
    matchTokens,
    consumed: pos,
    error,
    bombHard: error === 'F014',
  };
}
