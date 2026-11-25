// Test-only LZSS encoder, ported from reference/fwai_format.py lz_encode().
// The workbench itself only ever decodes; this exists so parser tests can
// prove decode(encode(x)) === x without depending on the Python toolchain.

const WINDOW = 4096;

export function lzEncode(data) {
  const out = [];
  let i = 0;
  const n = data.length;
  while (i < n) {
    const ctrlPos = out.length;
    out.push(0);
    let control = 0;
    for (let bit = 0; bit < 8; bit++) {
      if (i >= n) break;
      let bestLen = 0;
      let bestDist = 0;
      const windowStart = Math.max(0, i - WINDOW);
      const maxLenCap = n - i;
      for (let cand = windowStart; cand < i; cand++) {
        const maxLen = Math.min(
          maxLenCap,
          3 + Math.floor((65535 - (i - cand - 1)) / Math.max(i, 1)));
        let mlen = 0;
        while (mlen < maxLen && data[cand + mlen] === data[i + mlen]) mlen++;
        if (mlen >= 3 && mlen > bestLen) {
          bestLen = mlen;
          bestDist = i - cand;
        }
      }
      if (bestLen >= 3) {
        const raw16 = (bestDist - 1) + (bestLen - 3) * i;
        out.push(raw16 & 0xff, (raw16 >> 8) & 0xff);
        i += bestLen;
      } else {
        control |= 1 << bit;
        out.push(data[i]);
        i++;
      }
    }
    out[ctrlPos] = control;
  }
  return new Uint8Array(out);
}
