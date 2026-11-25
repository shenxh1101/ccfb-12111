// Report export. Both formats are rendered from the exact same result object
// the UI lists (the caller passes the stored analysis result), so an export
// can never disagree with what the user saw on screen.

import { RULES } from '../src/rules.js';

export function exportJson(result) {
  return JSON.stringify(result, null, 2);
}

function fmtHex(n) {
  return `0x${Number(n).toString(16).toUpperCase().padStart(8, '0')}`;
}

function severityBadge(s) {
  return s.toUpperCase();
}

export function exportMarkdown(result) {
  const lines = [];
  const h = result.header;
  lines.push(`# 固件审计报告：${result.fileName}`);
  lines.push('');
  lines.push(`- 导出时间：${new Date().toISOString()}`);
  lines.push(`- 文件大小：${result.fileSize} 字节`);
  lines.push(`- SHA-256：\`${result.sha256}\``);
  lines.push(`- 规则命中总数：${result.summary.totalFindings}`);
  lines.push('');

  lines.push('## 1. 文件头');
  if (!h) {
    lines.push('');
    lines.push('> 文件头不可解析，后续结构分析未执行。');
  } else {
    lines.push('');
    lines.push('| 字段 | 值 |');
    lines.push('|---|---|');
    lines.push(`| magic | ${h.magic} |`);
    lines.push(`| headerVersion | ${h.headerVersion} |`);
    lines.push(`| headerSize | ${h.headerSize} |`);
    lines.push(`| fileSize（声明） | ${h.fileSize} |`);
    lines.push(`| partitionTableOffset | ${h.partitionTableOffset} (${fmtHex(h.partitionTableOffset)}) |`);
    lines.push(`| partitionCount | ${h.partitionCount} |`);
    lines.push(`| flags | ${h.flags} (0b${h.flags.toString(2).padStart(16, '0')}) |`);
    lines.push(`| headerCrc32 | ${h.headerCrc32} (${fmtHex(h.headerCrc32)}) |`);
  }
  lines.push('');

  lines.push('## 2. 分区视图');
  lines.push('');
  if (result.partitions.length === 0) {
    lines.push('_无可解析分区。_');
  } else {
    lines.push('| # | 名称 | 类型 | 偏移 | storedSize | rawSize | CRC | 状态 |');
    lines.push('|---:|---|---|---:|---:|---:|---|---|');
    for (const p of result.partitions) {
      const status = [
        p.unparseable ? '不可解析' : null,
        p.truncated ? '截断' : null,
        p.crcValid === false ? 'CRC错' : null,
        p.crcValid === true ? 'CRCOK' : null,
      ].filter(Boolean).join('/');
      lines.push(`| ${p.entryIndex} | ${p.name} | ${p.entryTypeLabel} | ${fmtHex(p.entryOffset)} | ${p.storedSize} | ${p.rawSize} | ${fmtHex(p.entryCrc32)} | ${status} |`);
    }
  }
  lines.push('');

  lines.push('## 3. 漏洞与规则命中');
  lines.push('');
  const c = result.summary.findingCounts;
  lines.push(`严重级别分布：critical ${c.critical} / high ${c.high} / medium ${c.medium} / low ${c.low} / info ${c.info}`);
  lines.push('');
  if (result.findings.length === 0) {
    lines.push('_无命中。_');
  } else {
    lines.push('| 规则 | 级别 | 偏移 | 分区# | 说明 |');
    lines.push('|---|---|---:|---:|---|');
    for (const f of result.findings) {
      lines.push(`| ${f.ruleId} | ${severityBadge(f.severity)} | ${fmtHex(f.offset)} | ${f.entryIndex} | ${f.message} |`);
    }
  }
  lines.push('');

  lines.push('## 4. 签名段');
  lines.push('');
  if (!result.signature) {
    lines.push('_本固件不含可解析签名段。_');
  } else {
    const s = result.signature;
    lines.push(`- 签名表项：#${s.entryIndex}`);
    lines.push(`- 算法：${s.algorithm}（1 = HMAC-SHA256）`);
    lines.push(`- 签名长度：${s.sigLength} 字节`);
    lines.push(`- publicData：\`${s.publicData ?? 'n/a'}\``);
    lines.push(`- 签名摘要 signedDigest（仅结构核对，不验真）：\`${s.signedDigest ?? 'n/a'}\``);
  }
  lines.push('');

  lines.push('## 5. 规则字典');
  lines.push('');
  const used = new Set(result.findings.map((f) => f.ruleId));
  if (used.size === 0) {
    lines.push('_本次分析无命中规则。_');
  } else {
    lines.push('| 规则 | 级别 | 含义 |');
    lines.push('|---|---|---|');
    for (const id of [...used].sort()) {
      const [sev, msg] = RULES[id];
      lines.push(`| ${id} | ${sev} | ${msg} |`);
    }
  }
  lines.push('');
  lines.push('---');
  lines.push('由离线固件审计工作台生成，全部解析在浏览器本地完成。');
  return lines.join('\n');
}

export function downloadText(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
