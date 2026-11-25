// FWAI workbench application shell.
// All parsing happens in web/worker.js (off-main-thread); this file only
// handles routing, rendering and IndexedDB persistence.

import { idbAll, idbPut, idbDelete, idbUpdateTags,
  filterRecords, allTags, allRuleIds } from './library-db.js';
import { exportJson, exportMarkdown, downloadText } from './report.js';
import { RULES } from '../src/rules.js';

const state = {
  result: null,          // analysis result of the currently viewed firmware
  currentBlob: null,
  currentSource: null,   // 'upload' | 'golden' | 'library'
  worker: null,
  progress: null,
  cancelled: false,
  library: [],
  golden: [],
  filters: { tags: [], ruleIds: [] },
  lastNotice: null,
};

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hex8 = (n) => `0x${Number(n).toString(16).toUpperCase().padStart(8, '0')}`;
const fmtSize = (n) => n < 1024 ? `${n} B`
  : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB`
    : `${(n / 1048576).toFixed(2)} MiB`;
const sevClass = (sev) => `sev sev-${sev}`;

// --------------------------------------------------------------------------- //
// Worker lifecycle
// --------------------------------------------------------------------------- //

function ensureWorker() {
  if (state.worker) return state.worker;
  const worker = new Worker('./worker.js', { type: 'module' });
  worker.onmessage = async (ev) => {
    const msg = ev.data;
    if (msg.type === 'progress') {
      state.progress = msg;
      renderProgress();
    } else if (msg.type === 'done') {
      state.cancelled = msg.cancelled;
      const notice = msg.cancelled
        ? { kind: 'warn',
            text: msg.result
              ? '分析已取消，已产生的结果已保留，可在其他视图中查看。'
              : '分析已取消（取消发生在首个结果产生前）。' }
        : msg.error
          ? { kind: 'err', text: `分析失败：${msg.error}` }
          : null;
      if (msg.result) {
        state.result = msg.result;
        await persistCurrent();
      }
      state.progress = null;
      state.lastNotice = notice;
      await renderAll();
      if (!msg.cancelled && !msg.error) {
        location.hash = '#/partitions';
      }
    }
  };
  worker.onerror = (ev) => {
    state.lastNotice = { kind: 'err', text: `Worker 错误：${ev.message}` };
    renderAll();
  };
  state.worker = worker;
  return worker;
}

async function analyze(file, source = 'upload') {
  state.currentBlob = file;
  state.currentSource = source;
  state.result = null;
  state.cancelled = false;
  state.lastNotice = null;
  state.progress = { phase: 'queued', percent: 0, detail: file.name };
  renderAll();
  ensureWorker().postMessage({ type: 'analyze', file });
}

function cancelAnalysis() {
  state.worker?.postMessage({ type: 'cancel' });
}

async function persistCurrent() {
  if (!state.result || !state.currentBlob) return;
  const r = state.result;
  const record = {
    id: r.sha256.slice(0, 16),
    fileName: r.fileName,
    size: r.fileSize,
    sha256: r.sha256,
    tags: state.golden.find((g) => g.sha256 === r.sha256)?.tags ?? [],
    ruleIds: [...new Set(r.findings.map((f) => f.ruleId))].sort(),
    result: r,
    blob: state.currentBlob,
    createdAt: Date.now(),
    lastAnalyzedAt: Date.now(),
    source: state.currentSource,
  };
  await idbPut(record);
  state.library = await idbAll();
}

// --------------------------------------------------------------------------- //
// Golden corpus loading
// --------------------------------------------------------------------------- //

async function loadGoldenManifest() {
  try {
    const resp = await fetch('../golden/manifest.json');
    if (!resp.ok) throw new Error(resp.statusText);
    const manifest = await resp.json();
    state.golden = manifest.samples;
    $('#golden-status').textContent = `golden 样本 ${state.golden.length} 个已就绪`;
    $('#golden-status').className = 'golden-status ok';
  } catch {
    state.golden = [];
    $('#golden-status').textContent = 'golden 目录不可达（需经 HTTP 服务打开）';
  }
}

async function analyzeGolden(sample) {
  const resp = await fetch(`../golden/samples/${encodeURIComponent(sample.fileName)}`);
  const blob = await resp.blob();
  const file = new File([blob], sample.fileName, { type: 'application/octet-stream' });
  await analyze(file, 'golden');
}

// --------------------------------------------------------------------------- //
// Views
// --------------------------------------------------------------------------- //

function viewUpload() {
  const g = state.golden.map((s) => `
    <div class="golden-item" data-golden="${esc(s.fileName)}">
      <div class="gi-title">${esc(s.title)}</div>
      <div class="gi-meta">${esc(s.fileName)} · ${fmtSize(s.size)}</div>
      <div class="gi-meta" style="margin-top:4px">
        ${s.ruleIds.length
          ? s.ruleIds.map((r) => `<span class="pill warn">${r}</span>`).join(' ')
          : '<span class="pill ok">无命中</span>'}
      </div>
      <div class="gi-tags">${s.tags.map((t) => `<span class="pill">${esc(t)}</span>`).join('')}</div>
    </div>`).join('');

  return `
    <h1>上传分析</h1>
    <p class="page-desc">固件文件全程留在浏览器内，经 Web Worker 分块读取与解析，不上传任何服务器。</p>
    ${state.lastNotice
      ? `<div class="banner ${state.lastNotice.kind}">${esc(state.lastNotice.text)}</div>` : ''}
    <div class="dropzone" id="dropzone">
      <div class="dz-title">拖入固件文件，或点击选择</div>
      <div class="dz-sub">支持数百 MB 大文件 · 4 MiB 分块流式处理 · 可随时取消并保留已出结果</div>
      <input type="file" id="file-input">
    </div>
    <div class="progress-wrap" id="progress-wrap" hidden>
      <div class="progress-bar"><div class="progress-fill" id="progress-fill"></div></div>
      <div class="progress-meta">
        <span id="progress-detail">等待开始…</span>
        <span id="progress-percent">0%</span>
      </div>
      <div class="btn-row">
        <button class="btn danger" id="btn-cancel">取消分析</button>
      </div>
    </div>
    <h2>Golden 样本库（点击即分析，结果应与 golden/expected 逐字段一致）</h2>
    <div class="golden-list">${g || '<div class="empty-state">manifest 未加载</div>'}</div>
  `;
}

function renderProgress() {
  const wrap = $('#progress-wrap');
  if (!wrap) return;
  if (!state.progress) {
    wrap.hidden = true;
    return;
  }
  wrap.hidden = false;
  const pct = Math.round(state.progress.percent ?? 0);
  $('#progress-fill').style.width = `${pct}%`;
  $('#progress-percent').textContent = `${pct}%`;
  $('#progress-detail').textContent =
    `${state.progress.phase} — ${state.progress.detail ?? ''}`;
}

function bindUpload() {
  const dz = $('#dropzone');
  const input = $('#file-input');
  dz.addEventListener('click', () => input.click());
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
  dz.addEventListener('drop', (e) => {
    e.preventDefault();
    dz.classList.remove('drag');
    if (e.dataTransfer.files[0]) analyze(e.dataTransfer.files[0]);
  });
  input.addEventListener('change', () => {
    if (input.files[0]) analyze(input.files[0]);
  });
  $('#btn-cancel')?.addEventListener('click', cancelAnalysis);
  document.querySelectorAll('[data-golden]').forEach((el) => {
    el.addEventListener('click', () => {
      const s = state.golden.find((x) => x.fileName === el.dataset.golden);
      if (s) analyzeGolden(s);
    });
  });
}

function viewPartitions() {
  const r = state.result;
  if (!r) return emptyView('分区视图', '先在「上传分析」中载入一个固件。');
  const rows = r.partitions.map((p) => {
    const lz = p.detail?.lz;
    const sig = p.detail?.signature;
    const detail = lz
      ? `控制字节 ${lz.controlBytes} · 字面量 ${lz.literalTokens} · 匹配 ${lz.matchTokens}<br>解压 ${lz.decompressedSize} B · 消费 ${lz.consumed}/${p.storedSize} B`
      : sig
        ? `algo=${sig.algorithm ?? '?'} · sigLen=${sig.sigLength ?? '?'}`
        : p.detail?.raw ? `原始数据 ${p.detail.raw.bytes} B` : '—';
    const flags = [
      p.unparseable ? '<span class="pill warn">不可解析</span>' : '',
      p.truncated ? '<span class="pill warn">截断</span>' : '',
      p.crcValid === true ? '<span class="pill ok">CRC OK</span>' : '',
      p.crcValid === false ? '<span class="pill warn">CRC 错</span>' : '',
    ].join(' ');
    return `<tr>
      <td class="mono">${p.entryIndex}</td>
      <td>${esc(p.name)}</td>
      <td><span class="pill accent">${p.entryTypeLabel}</span></td>
      <td class="mono">${hex8(p.entryOffset)}</td>
      <td class="mono">${p.storedSize}</td>
      <td class="mono">${p.rawSize}</td>
      <td class="mono dim">${hex8(p.entryCrc32)}</td>
      <td>${flags}</td>
      <td class="dim" style="font-size:11.5px">${detail}</td>
    </tr>`;
  }).join('');
  return `
    <h1>分区视图</h1>
    <p class="page-desc">${esc(r.fileName)} · ${fmtSize(r.fileSize)} · 共 ${r.partitions.length} 个表项</p>
    ${r.partitions.length ? `<div class="table-wrap"><table>
      <thead><tr><th>#</th><th>名称</th><th>类型</th><th>entryOffset</th>
        <th>storedSize</th><th>rawSize</th><th>CRC-32</th><th>状态</th><th>段细节</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`
      : '<div class="empty-state"><div class="es-title">无可解析分区</div>头级错误或分区表不可读时会出现此情况。</div>'}
  `;
}

function viewFindings() {
  const r = state.result;
  if (!r) return emptyView('漏洞列表', '先在「上传分析」中载入一个固件。');
  const c = r.summary.findingCounts;
  const stats = ['critical', 'high', 'medium', 'low', 'info'].map((sev) =>
    `<div class="stat"><div class="num sev sev-${sev}" style="background:transparent">${c[sev]}</div>
      <div class="lbl">${sev}</div></div>`).join('');
  const rows = r.findings.map((f) => `<tr>
      <td class="mono"><strong>${f.ruleId}</strong></td>
      <td><span class="${sevClass(f.severity)}">${f.severity}</span></td>
      <td class="mono"><code class="offset">${hex8(f.offset)}</code> <span class="faint">(${f.offset})</span></td>
      <td class="mono">${f.entryIndex < 0 ? '<span class="faint">头/表</span>' : f.entryIndex}</td>
      <td>${esc(f.message)}</td>
    </tr>`).join('');
  return `
    <h1>漏洞列表</h1>
    <p class="page-desc">每条命中给出绝对字节偏移；排序与 golden JSON 完全一致。</p>
    <div class="grid-cards" style="margin-bottom:18px">${stats}
      <div class="stat"><div class="num">${r.summary.totalFindings}</div><div class="lbl">总命中</div></div>
    </div>
    ${r.findings.length ? `<div class="table-wrap"><table>
      <thead><tr><th>规则</th><th>级别</th><th>偏移</th><th>分区#</th><th>说明</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`
      : '<div class="empty-state"><div class="es-title">无命中</div>该固件通过全部审计规则。</div>'}
  `;
}

async function viewLibrary() {
  state.library = await idbAll();
  const tags = allTags(state.library);
  const ruleIds = allRuleIds(state.library);
  const filtered = filterRecords(state.library, state.filters);
  const tagChips = tags.map((t) =>
    `<span class="chip ${state.filters.tags.includes(t) ? 'on' : ''}" data-tag="${esc(t)}">${esc(t)}</span>`).join('');
  const ruleOptions = ['<option value="">全部规则</option>']
    .concat(ruleIds.map((id) =>
      `<option value="${id}" ${state.filters.ruleIds.includes(id) ? 'selected' : ''}>${id} — ${esc(RULES[id]?.[1] ?? '')}</option>`)).join('');
  const rows = filtered.map((rec) => {
    const r = rec.result;
    return `<tr class="lib-row" data-id="${esc(rec.id)}">
      <td>
        <div style="font-weight:600">${esc(rec.fileName)}</div>
        <div class="faint mono" style="font-size:11px;margin-top:3px">${esc(rec.sha256.slice(0, 24))}…</div>
        <div class="tag-edit">
          <input class="tag-input" placeholder="加标签后回车，逗号分隔" data-tagfor="${esc(rec.id)}">
        </div>
        <div class="tag-set" style="margin-top:5px">
          ${rec.tags.map((t) => `<span class="pill">${esc(t)}</span>`).join('') || '<span class="faint">无标签</span>'}
        </div>
      </td>
      <td class="mono dim">${fmtSize(rec.size)}</td>
      <td><span class="pill ${rec.source === 'golden' ? 'accent' : ''}">${rec.source}</span></td>
      <td>${rec.ruleIds.map((id) =>
        `<span class="pill ${RULES[id]?.[0] === 'critical' || RULES[id]?.[0] === 'high' ? 'warn' : ''}">${id}</span>`).join(' ') || '<span class="pill ok">无命中</span>'}</td>
      <td class="mono dim">${new Date(rec.createdAt).toLocaleString()}</td>
      <td>
        <button class="btn" data-reanalyze="${esc(rec.id)}">查看</button>
        <button class="btn danger" data-delete="${esc(rec.id)}">删除</button>
      </td>
    </tr>`;
  }).join('');
  return `
    <h1>样本库</h1>
    <p class="page-desc">IndexedDB 本地持久化 · 共 ${state.library.length} 个样本，当前过滤后 ${filtered.length} 个</p>
    <div class="filters">
      <label>标签（AND）：</label>${tagChips || '<span class="faint">暂无标签</span>'}
      <label style="margin-left:14px">命中规则（OR）：</label>
      <select id="rule-filter" multiple size="1" style="min-width:260px">${ruleOptions}</select>
      <button class="btn" id="clear-filters">清除过滤</button>
    </div>
    ${filtered.length ? `<div class="table-wrap"><table>
      <thead><tr><th>样本 / 标签</th><th>大小</th><th>来源</th><th>命中规则</th><th>入库时间</th><th>操作</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`
      : '<div class="empty-state"><div class="es-title">没有匹配的样本</div>上传或从 golden 列表分析后会自动入库。</div>'}
  `;
}

function bindLibrary() {
  document.querySelectorAll('[data-tag]').forEach((el) => {
    el.addEventListener('click', () => {
      const t = el.dataset.tag;
      const arr = state.filters.tags;
      state.filters.tags = arr.includes(t) ? arr.filter((x) => x !== t) : [...arr, t];
      renderAll();
    });
  });
  $('#rule-filter')?.addEventListener('change', (e) => {
    state.filters.ruleIds = [...e.target.selectedOptions].map((o) => o.value).filter(Boolean);
    renderAll();
  });
  $('#clear-filters')?.addEventListener('click', () => {
    state.filters = { tags: [], ruleIds: [] };
    renderAll();
  });
  document.querySelectorAll('[data-delete]').forEach((el) => {
    el.addEventListener('click', async () => {
      await idbDelete(el.dataset.delete);
      renderAll();
    });
  });
  document.querySelectorAll('[data-reanalyze]').forEach((el) => {
    el.addEventListener('click', async () => {
      const rec = state.library.find((x) => x.id === el.dataset.reanalyze);
      if (!rec) return;
      state.result = rec.result;
      state.currentBlob = rec.blob;
      state.currentSource = rec.source;
      renderAll();
      location.hash = '#/partitions';
    });
  });
  document.querySelectorAll('[data-tagfor]').forEach((el) => {
    el.addEventListener('keydown', async (e) => {
      if (e.key !== 'Enter') return;
      const id = el.dataset.tagfor;
      const rec = state.library.find((x) => x.id === id);
      const added = el.value.split(',').map((s) => s.trim()).filter(Boolean);
      await idbUpdateTags(id, [...(rec?.tags ?? []), ...added]);
      renderAll();
    });
  });
}

function viewReport() {
  const r = state.result;
  if (!r) return emptyView('报告导出', '先在「上传分析」中载入一个固件。');
  const md = exportMarkdown(r);
  const sig = r.signature;
  return `
    <h1>报告导出</h1>
    <p class="page-desc">报告由当前结果对象直接渲染，内容与漏洞列表、分区视图完全一致。</p>
    <div class="report-box" style="margin-bottom:16px">
      <dl class="kv">
        <dt>文件</dt><dd>${esc(r.fileName)}</dd>
        <dt>大小</dt><dd>${r.fileSize} 字节（${fmtSize(r.fileSize)}）</dd>
        <dt>SHA-256</dt><dd>${esc(r.sha256)}</dd>
        <dt>命中总数</dt><dd>${r.summary.totalFindings}
          （critical ${r.summary.findingCounts.critical} / high ${r.summary.findingCounts.high}
          / medium ${r.summary.findingCounts.medium} / low ${r.summary.findingCounts.low}
          / info ${r.summary.findingCounts.info}）</dd>
        <dt>签名摘要</dt><dd>${sig?.signedDigest ? esc(sig.signedDigest) : '<span class="faint">无 / 不可计算</span>'}</dd>
      </dl>
      <div class="btn-row">
        <button class="btn primary" id="export-md">导出 Markdown</button>
        <button class="btn primary" id="export-json">导出 JSON</button>
      </div>
    </div>
    <h2>Markdown 预览</h2>
    <pre class="report-preview">${esc(md)}</pre>
  `;
}

function bindReport() {
  const r = state.result;
  if (!r) return;
  const base = r.fileName.replace(/\.[^.]+$/, '') || 'firmware';
  $('#export-md')?.addEventListener('click', () =>
    downloadText(`${base}-audit.md`, exportMarkdown(r), 'text/markdown'));
  $('#export-json')?.addEventListener('click', () =>
    downloadText(`${base}-audit.json`, exportJson(r), 'application/json'));
}

function emptyView(title, hint) {
  return `<h1>${esc(title)}</h1>
    <div class="empty-state" style="margin-top:30px">
      <div class="es-title">${esc(hint)}</div>
      <a class="btn primary" href="#/upload" style="display:inline-block;margin-top:12px;text-decoration:none">去上传</a>
    </div>`;
}

// --------------------------------------------------------------------------- //
// Router
// --------------------------------------------------------------------------- //

const ROUTES = {
  upload: { el: 'page-upload', render: viewUpload, bind: bindUpload },
  partitions: { el: 'page-partitions', render: viewPartitions, bind: () => {} },
  findings: { el: 'page-findings', render: viewFindings, bind: () => {} },
  library: { el: 'page-library', render: viewLibrary, bind: bindLibrary },
  report: { el: 'page-report', render: viewReport, bind: bindReport },
};

async function renderAll() {
  updateCurrentFileChip();
  const route = location.hash.replace('#/', '') || 'upload';
  for (const [name, cfg] of Object.entries(ROUTES)) {
    const el = $(`#${cfg.el}`);
    el.hidden = name !== route;
  }
  document.querySelectorAll('#nav a').forEach((a) =>
    a.classList.toggle('active', a.dataset.route === route));
  const cfg = ROUTES[route] ?? ROUTES.upload;
  const el = $(`#${cfg.el}`);
  el.innerHTML = await cfg.render();
  cfg.bind();
  renderProgress();
}

function updateCurrentFileChip() {
  const chip = $('#current-file');
  if (state.result) {
    chip.classList.remove('empty');
    chip.textContent = `${state.result.fileName} · ${fmtSize(state.result.fileSize)} · ${state.result.summary.totalFindings} 命中`;
  } else {
    chip.classList.add('empty');
    chip.textContent = '尚未载入固件';
  }
}

window.addEventListener('hashchange', renderAll);
loadGoldenManifest().then(renderAll);
