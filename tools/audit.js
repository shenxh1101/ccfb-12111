// Command-line firmware audit entry point — same parser as the browser,
// usable in CI / offline batch jobs.
//
//   node tools/audit.js <firmware.fw> [--json] [--md]
//
// Default: print a short human summary. --json emits the full golden-shape
// result document; --md emits the same Markdown report the workbench exports.

import { readFileSync } from 'node:fs';
import { parseBytes } from '../src/parser.js';
import { exportMarkdown } from '../web/report.js';

const [, , file, ...flags] = process.argv;
if (!file) {
  console.error('usage: node tools/audit.js <firmware.fw> [--json] [--md]');
  process.exit(2);
}

const bytes = new Uint8Array(readFileSync(file));
const result = await parseBytes(bytes, file.split('/').pop());

if (flags.includes('--json')) {
  console.log(JSON.stringify(result, null, 2));
} else if (flags.includes('--md')) {
  console.log(exportMarkdown(result));
} else {
  const c = result.summary.findingCounts;
  console.log(`file:     ${result.fileName} (${result.fileSize} B)`);
  console.log(`sha256:   ${result.sha256}`);
  console.log(`parts:    ${result.summary.partitionsTotal}`
    + ` (truncated ${result.summary.partitionsTruncated},`
    + ` unparseable ${result.summary.partitionsUnparseable})`);
  console.log(`findings: ${result.summary.totalFindings}`
    + `  critical=${c.critical} high=${c.high} medium=${c.medium}`
    + ` low=${c.low} info=${c.info}`);
  for (const f of result.findings) {
    console.log(`  ${f.ruleId}  ${f.severity.padEnd(8)}`
      + ` off=0x${f.offset.toString(16).padStart(8, '0').toUpperCase()}`
      + ` part=${String(f.entryIndex).padStart(2)}  ${f.message}`);
  }
}

process.exit(result.summary.totalFindings === 0 ? 0 : 1);
