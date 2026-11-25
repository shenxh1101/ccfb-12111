# 审计规则目录

规则 ID 与 `docs/firmware-format.md` 第 7 节配套。所有实现（Python 参考实现、JS 解析器）必须产出相同 ID、相同偏移、相同严重级别的命中结果。

偏移约定：表项级规则的 `offset` 为该表项段数据起始偏移（`entryOffset`）；头/表级规则的 `offset` 为问题字段在文件中的绝对偏移；`entryIndex = -1` 表示不属于任何表项。

## 严重级别定义

| 级别 | 含义 |
|---|---|
| critical | 解析无法继续或结构根本不可信（坏头、表不可读） |
| high | 可被利用的内存/资源安全问题（越界、解压炸弹、畸形压缩流） |
| medium | 完整性或签名问题（CRC 错、签名异常、保留位污染） |
| low | 规范偏差但不影响内存安全（尺寸不一致、加密标志） |
| info | 信息性提示（未知段类型） |

## 规则清单

| ID | 级别 | 名称 | 触发条件 | 偏移 |
|---|---|---|---|---|
| F001 | critical | truncated-header | 文件不足 32 字节，或魔数正确但头被截断 | 0 |
| F002 | critical | bad-header-crc | `headerCrc32` 与前 28 字节计算值不符 | 20 |
| F003 | critical | bad-magic | 前 4 字节不是 `FWAI` | 0 |
| F004 | critical | table-out-of-bounds | 分区表区间 `[tableOffset, tableOffset+36*count)` 超出文件，或 count>128 | `partitionTableOffset` 字段偏移 12；count 超限用 16 |
| F005 | high | entry-out-of-bounds | 表项段区间起点超出文件、32 位加法溢出，或末端超出文件 | `entryOffset` |
| F006 | high | lz-truncated | LZ 输入先耗尽而输出未达 `rawSize` | `entryOffset` |
| F007 | high | lz-invalid-token | 输出为空时出现匹配 token，或 token 读取越过段边界 | `entryOffset` |
| F008 | high | signature-malformed | 签名段长度不足 `4 + sigLength + 32`，或结构字段不可读 | `entryOffset` |
| F009 | medium | signature-too-long | `sigLength > 512` | `entryOffset + 2` |
| F010 | low | lz-size-mismatch | 输出达到 `rawSize` 后仍有未消费压缩字节，或 RAW 段 `rawSize != storedSize` | `entryOffset` |
| F011 | info | unknown-entry-type | `entryType` 不属于 {1,2,3} | 表项内偏移 16（绝对偏移给出） |
| F012 | high | partition-overlap | 两个可解析表项的 `[entryOffset, entryOffset+storedSize)` 区间相交（端点相接不算） | 后一个表项的 `entryOffset` |
| F013 | medium | crc-mismatch | 段 CRC-32 与 `entryCrc32` 不符（截断段按文件内前缀计算） | `entryOffset` |
| F014 | high | decompression-bomb | 声明比率 >100 且 rawSize>1MiB，或解压输出达到 16 MiB 硬上限 | `entryOffset` |
| F015 | medium | signature-too-short | `sigLength < 32` | `entryOffset + 2` |
| F016 | medium | reserved-nonzero | 头保留 8 字节、表项保留 2 处（偏移 17 的 1 字节、偏移 34 的 2 字节）任一字节非 0，或 flags 保留位（bit2–15）非 0 | 该保留字段的绝对偏移 |
| F017 | medium | multiple-signatures | 存在第 2 个及以后 `entryType=3` 的表项 | `entryOffset` |
| F018 | medium | unknown-signature-algorithm | 签名段 `sigAlgorithm != 1` | `entryOffset` |
| F019 | low | encrypted-flag | 头 `flags` 的 bit1（加密位）被置位 | 18 |
| F020 | low | file-size-mismatch | 头 `fileSize` 与实际文件长度不一致 | 8 |

## 命中排序

`findings` 数组严格按 `(offset 升序, ruleId 字典序升序, entryIndex 升序)` 排序后输出。同一表项同一规则只命中一次。

## 解析流水线（确定性顺序）

为保证不同实现结果一致，检查按以下阶段执行；后一阶段依赖前一阶段产物，但同阶段内规则按上表排序归并：

1. **头阶段**：长度 → 魔数 → 头尺寸/版本 → 头 CRC → 保留位 → flags → fileSize → 表越界预判（count 上限）。
2. **表阶段**：逐项读取 36 字节；表项保留位检查（F016）在此阶段。
3. **段阶段（按表项顺序）**：越界（F005）→ 类型分派 → 类型专属检查（LZ/签名/RAW 尺寸）→ CRC（F013）。
4. **全局阶段**：重叠检查（F012，仅可解析表项）→ 多签名（F017）→ 签名摘要计算 → 汇总计数。

## 解压炸弹参数（两份实现共享）

| 参数 | 值 |
|---|---|
| `MAX_OUTPUT` 硬上限 | 16 MiB = 16,777,216 字节 |
| 声明比率阈值 | 100 |
| 声明比率附加条件 | `rawSize > 1 MiB (1,048,576)` |
| LZ 窗口 | 4096 字节（格式约束，解码仅用 distance 回指，不单独限长） |
