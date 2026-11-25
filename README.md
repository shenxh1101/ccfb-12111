# FWAI 离线固件审计工作台

一款**完全在浏览器本地运行**的固件包审计工具：拖入固件文件即可解析分区表、LZ 压缩段、签名段并执行越界 / 重叠 / 解压炸弹 / 签名长度等安全检查。无任何网络上报，无构建步骤，无第三方运行时依赖。

## 为什么有这个项目

老设备固件的解析模块曾出过一次堆溢出，补丁打过但无法证明"干净"。本工作台用一套**带硬边界的新解析器**替换历史实现，并通过与参考解析器的逐字段 golden 对照来证明行为正确：

- 所有偏移在解引用前都与真实文件长度做边界检查，不存在可越过缓冲的读路径；
- 解压输出有 16 MiB 硬上限，压缩流解码每 2 万个 token 协作式让出事件循环（可取消、不卡页面）；
- 畸形输入只产生规则 ID，解析器永不抛异常；
- 故意截断的样本（`03-truncated-header`、`07-partial-truncated`）是固定测试夹具。

## 目录结构

```
docs/                     格式规范（唯一格式依据）
  firmware-format.md      FWAI 二进制布局：文件头 / 分区表 / LZ 段 / 签名段
  audit-rules.md          F001–F020 审计规则目录、严重级别、偏移语义
reference/                Python 参考实现（仅标准库，python3 -I 运行）
  fwai_format.py          LZSS 编解码 + 封包器 + 参考审计解析器（golden 定义来源）
  generate_samples.py     16 个样本生成器 + golden JSON 导出
golden/
  samples/*.fw            16 个固件样本（含 2 个截断样本、1 个 12 MiB 大文件）
  expected/*.json         参考解析器输出，JS 解析器必须逐字段一致
  manifest.json           样本目录（标签、命中规则、SHA-256）
src/                      浏览器/Node 共用的纯 ESM 解析引擎
  rules.js                规则常量（消息字符串属于 golden 契约）
  reader.js               MemoryReader / ChunkedReader（4 MiB 分块、LRU 淘汰）
  lz.js                   带硬上限与协作让出的 LZSS 解码器
  sha256.js               增量 SHA-256（流式，无依赖）
  parser.js               四阶段审计流水线 + 取消保留部分结果
web/                      工作台 SPA（五个页面）
  index.html/styles.css   布局与深色主题
  app.js                  路由、视图渲染、IndexedDB 样本库
  worker.js               Web Worker：解析全程离开主线程
  report.js               Markdown / JSON 报告导出
  library-db.js           IndexedDB 持久化与标签/规则过滤
test/                     node --test 套件（27 个用例）
tools/
  serve.js                零依赖静态服务器
  audit.js                CLI 审计入口（CI / 批量场景）
  e2e-check.js            CDP 驱动的无头 Chrome 端到端检查
```

## 快速开始

```bash
# 1. 启动静态服务（需要 HTTP 环境以支持 Worker / fetch）
npm run serve
# 打开 http://localhost:8080/web/index.html

# 2. 跑 golden 对照与全部单元测试
npm test

# 3. 命令行审计单个固件（退出码 0=无命中，1=有命中）
node tools/audit.js golden/samples/08-overlap.fw
node tools/audit.js some.fw --json > report.json
node tools/audit.js some.fw --md   > report.md
```

重新生成 golden 样本（修改参考实现后）：`python3 -I reference/generate_samples.py`，随后 `npm test` 必须全绿。

## 五个页面

| 页面 | 能力 |
|---|---|
| 上传分析 | 拖拽/点选文件、4 MiB 分块流式读取、实时进度、**可取消且保留已出结果**；golden 样本卡片一键分析 |
| 分区视图 | 全部表项的偏移/尺寸/CRC/截断状态，LZ 段展示 token 统计与解压尺寸 |
| 漏洞列表 | F001–F020 命中，每条给出**绝对字节偏移**、所属分区、严重级别统计 |
| 样本库 | IndexedDB 持久化原始 Blob + 结果；自定义标签；按标签（AND）与命中规则（OR）过滤 |
| 报告导出 | Markdown 与 JSON 两种，由当前结果对象直接渲染，与页面列表内容一致 |

## 审计规则（20 条，详见 docs/audit-rules.md）

- **越界与结构**：F001 截断头、F003 坏魔数、F004 分区表越界、F005 段越界、F012 分区重叠、F020 文件尺寸不符
- **LZ 压缩段**：F006 流提前结束、F007 非法 token、F010 尺寸不符、F014 解压炸弹（声明比率 >100 且 rawSize>1 MiB，或输出触达 16 MiB 硬上限）
- **签名段**：F008 结构畸形、F009 过长（>512）、F015 过短（<32）、F017 多签名、F018 未知算法
- **完整性**：F002 头 CRC、F013 段 CRC、F016 保留位污染、F019 加密标志、F011 未知段类型

## 大文件与取消的设计

- `ChunkedReader` 以 4 MiB 为窗口按需 `blob.slice()` 读取，最多保留 3 个窗口（约 12 MiB 驻留），LRU 淘汰；
- SHA-256 用自实现的增量实现逐块喂入，几百 MB 文件不会被整体复制进内存；
- LZ 解码器每 20 000 个 token `await` 一个微任务，期间检查 `AbortSignal`；
- 取消时解析器把已收集的 findings 即时 finalize 并随取消异常返回，UI 展示"已取消，结果已保留"，其他视图可继续查看部分结果。

## Golden 契约的强度

`test/golden.test.js` 对 16 个样本做**递归深比较**（类型、键集合、数组长度、每个标量值），任何字段漂移都会报出具体 JSON 路径。规则消息字符串也是契约的一部分（`src/rules.js` 与 Python `RULES` 表逐字一致）。浏览器 E2E（`tools/e2e-check.js`）另外验证真实 Worker 链路的渲染结果与 golden JSON 一致。
