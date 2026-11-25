# FWAI 固件包格式规范

版本: 1.0
适用: 离线固件审计工作台（`FWAI` = FirmWare Audit Image，魔数 `0x49415746`）

本规范是所有解析器（C 参考解析器、Python 参考实现 `reference/`、浏览器侧 JS 解析器 `src/`）共同遵循的唯一格式依据。所有多字节整数均为 **小端序（little-endian）**，所有偏移均相对于文件起始，以字节为单位。

## 1. 整体布局

```
+------------------+ 偏移 0
| 文件头 (32 B)    |
+------------------+ 偏移 header.partitionTableOffset
| 分区表 (N ×36 B) |
+------------------+
| 段 1             |
+------------------+
| 段 2 ...         |
+------------------+
| 签名段           |   （type=3 的表项指向它）
+------------------+ EOF
```

文件中没有强制排列顺序：段的位置完全由分区表项中的 `entryOffset` 决定，解析器不得假设段在文件中的物理次序。

## 2. 文件头（32 字节，偏移 0）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 4 | `magic` | 必须为 ASCII `"FWAI"`，即字节 `46 57 41 49` |
| 4 | 2 | `headerVersion` | 头版本，当前为 `1` |
| 6 | 2 | `headerSize` | 本头长度，必须为 `32` |
| 8 | 4 | `fileSize` | 封包时写入的文件总长度（字节），用于与实际长度比对 |
| 12 | 4 | `partitionTableOffset` | 分区表起始偏移 |
| 16 | 2 | `partitionCount` | 分区表项数量，最大 128 |
| 18 | 2 | `flags` | 位域，见 §2.1 |
| 20 | 4 | `headerCrc32` | 前 28 字节（本字段清零后）的 CRC-32（IEEE 多项式，与 zlib/POSIX `crc32` 一致） |
| 24 | 8 | 保留 | 必须全 0 |

文件不足 32 字节时，不做任何字段访问，直接以 `F001 truncated-header` 终止解析。

### 2.1 flags 位域

| 位 | 名称 | 含义 |
|---:|---|---|
| 0 | `FLAG_SIGNED` | 包内含签名段 |
| 1 | `FLAG_ENCRYPTED` | 包内含加密内容（本工作台不支持，必须告警） |
| 2–15 | — | 保留，必须为 0 |

## 3. 分区表项（每项 36 字节）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 16 | `name` | ASCII 名称，不足 16 字节以 `0x00` 填充；解析时按首个 NUL 截断 |
| 16 | 1 | `entryType` | `1`=RAW 原始段，`2`=LZ 压缩段，`3`=SIGNATURE 签名段 |
| 17 | 1 | 保留 | 必须为 0 |
| 18 | 4 | `entryOffset` | 段数据起始偏移 |
| 22 | 4 | `storedSize` | 段在文件中占用的字节数 |
| 26 | 4 | `rawSize` | 段解压/展开后的逻辑字节数（RAW 段必须等于 `storedSize`） |
| 30 | 4 | `entryCrc32` | 段数据（`[entryOffset, entryOffset+storedSize)`）的 CRC-32 |
| 34 | 2 | 保留 | 必须为 0 |

### 3.1 越界语义（统一约定，所有实现必须一致）

对表项区间 `[entryOffset, entryOffset+storedSize)`：

1. 若 `entryOffset > actualFileSize` → `F005 entry-out-of-bounds`，该表项记为 `unparseable`，不读取任何字节，跳过后续段级检查。
2. 若 `entryOffset + storedSize` 以 32 位无符号整数溢出（`> 0xFFFFFFFF`）→ 同上，按 `F005` 处理。
3. 若区间起始在文件内但末端超出文件 → 先记 `F005`；对落在文件内的前缀仍尽量解析（LZ 段解压到截断点），段级其余检查照常进行；摘要标记 `truncated: true`。
4. 完整越界的表项不参与重叠检查与签名摘要计算。

## 4. LZ 压缩段（entryType = 2）

采用无专利限制的 LZSS 变体，窗口大小 4096 字节，纯字节流、无额外头。压缩数据按控制块组织：

### 4.1 控制块

每个控制块以 1 个 **控制字节** 起始，其 8 个位从低位到高位（bit0 → bit7）各对应一个 token，`1` 表示字面量，`0` 表示回溯匹配。8 个 token 处理完后读入下一个控制字节；不足 8 个 token 时以控制字节高位未使用位置 0 表示（编码器保证最后一个控制字节的未使用位为 0）。

### 4.2 token 编码

- **字面量 token（位=1）**：读取 1 字节，直接追加到输出。
- **匹配 token（位=0）**：读取 2 字节（小端）：
  - `distance = (raw16 % 输出当前长度) + 1`，取值范围 `[1, 当前输出长度]`
  - `length = floor(raw16 / 当前输出长度) + 3`
  - 从输出缓冲的 `当前长度 - distance` 位置逐字节拷贝 `length` 字节；允许 `length > distance`（重叠拷贝，字节逐个复制，天然支持 RLE 式重复）

匹配 token 在输出为空（当前长度 = 0）时出现属于畸形数据，报 `F007 lz-invalid-token`。

### 4.3 终止条件

解码器以 **达到 `rawSize` 为唯一正常终止条件**：输出达到 `rawSize` 后立即停止，控制字节/输入中剩余字节一律忽略（它们仍计入 `storedSize` 与 CRC 校验）。

- 输入先耗尽而输出未达 `rawSize` → `F006 lz-truncated`（该规则同时覆盖"段被文件截断"和"压缩流本身提前结束"两种情况）。
- 输出达到 `rawSize` 时仍有未消费的输入字节 → `F010 lz-size-mismatch`（声明尺寸与流不一致）。
- 输出在达到 `rawSize` 前超过 `MAX_OUTPUT = 16 MiB (16777216)` → `F014 decompression-bomb`，立即停止解压。

### 4.4 解压炸弹（F014）判定

满足任一条件即命中，按表项记录：

1. 声明比率 `rawSize / max(storedSize,1) > 100` 且 `rawSize > 1 MiB (1048576)`；或
2. 实际输出长度达到 `MAX_OUTPUT = 16 MiB`（硬上限，防止页面内存耗尽）。

## 5. 签名段（entryType = 3）

段数据布局：

| 偏移 | 长度 | 字段 |
|---:|---:|---|
| 0 | 2 | `sigAlgorithm`，`1` = HMAC-SHA256（本版本唯一合法值） |
| 2 | 2 | `sigLength`，签名字节数 |
| 4 | `sigLength` | 签名字节 |
| 4+sigLength | 32 | `publicData`（随包携带的公钥/密钥标识，32 字节，不参与密码学验证） |

### 5.1 检查规则

- `sigLength < 32` → `F015 signature-too-short`
- `sigLength > 512` → `F009 signature-too-long`
- 段完整长度不足 `4 + sigLength + 32` → `F008 signature-malformed`（若同时已命中 `F005`，两条都保留）
- 每个固件包最多 1 个签名表项；多于 1 个时第 2 个及以后报 `F017 multiple-signatures`
- `sigAlgorithm != 1` → `F018 unknown-signature-algorithm`

### 5.2 签名摘要（解析器只做结构核对，不验真）

签名摘要 `signedDigest` 定义为对以下范围拼接后的 SHA-256 十六进制字符串：

1. 文件头 `[0, 32)`；
2. 分区表完整区间 `[partitionTableOffset, partitionTableOffset + 32*partitionCount)`；
3. 除签名段自身之外、所有**完整落在文件内**的表项段数据，按表项在分区表中的顺序拼接。

仅当签名段结构完整（无 `F005/F008`）且上述所有区间可完整读取时才计算 `signedDigest`，否则该字段为 `null`。本工作台离线运行、不持有厂商密钥，不进行密码学真伪验证。

## 6. 校验和

- 头 CRC：`headerCrc32` 覆盖偏移 `[0, 28)`。该字段自身位于 `[20,24)`、落在覆盖区间内，因此**写入方与验证方都必须把 `[20,24)` 按全 0 处理**后再计算（封包时先清零计算再回填；校验时临时清零后重算并与存储值比较）。
- 段 CRC：`entryCrc32` 覆盖段的**实际存储字节**；段被截断时只对文件内前缀计算，不匹配仍报 `F013`。
- CRC-32 采用标准 IEEE 802.3 多项式 `0xEDB88320`（反射形式），初始值 `0xFFFFFFFF`，结果异或 `0xFFFFFFFF`。

## 7. 审计规则目录

完整规则清单（ID、严重级别、偏移来源）见 [`audit-rules.md`](./audit-rules.md)。解析结果中的 `findings` 数组按 `(offset, ruleId, entryIndex)` 升序排列，规则 ID 的字符串顺序不影响排序。

## 8. 解析输出 JSON 结构（golden 契约）

参考解析器与 JS 解析器必须输出**逐字段一致**的 JSON：

```json
{
  "schemaVersion": 1,
  "fileName": "sample.fw",
  "fileSize": 12345,
  "sha256": "…",
  "header": {
    "magic": "FWAI",
    "headerVersion": 1,
    "headerSize": 32,
    "fileSize": 12345,
    "partitionTableOffset": 32,
    "partitionCount": 2,
    "flags": 1,
    "headerCrc32": 3735928559,
    "reserved": "0000000000000000"
  },
  "partitions": [
    {
      "entryIndex": 0,
      "name": "boot",
      "entryType": 2,
      "entryTypeLabel": "LZ",
      "entryOffset": 104,
      "storedSize": 500,
      "rawSize": 1200,
      "entryCrc32": 123456,
      "crcValid": true,
      "truncated": false,
      "unparseable": false,
      "detail": { "lz": { "controlBytes": 70, "literalTokens": 300,
                          "matchTokens": 120, "consumed": 498,
                          "decompressedSize": 1200 } }
    }
  ],
  "findings": [
    { "ruleId": "F014", "severity": "high", "offset": 104,
      "entryIndex": 0, "message": "…" }
  ],
  "signature": {
    "present": true,
    "entryIndex": 4,
    "algorithm": 1,
    "sigLength": 32,
    "publicData": "…64 hex chars…",
    "signedDigest": "…64 hex chars…"
  },
  "summary": {
    "findingCounts": { "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 0 },
    "totalFindings": 6,
    "partitionsTotal": 5,
    "partitionsTruncated": 0,
    "partitionsUnparseable": 0
  }
}
```

约定：

- 无签名段或签名段不可解析时，`signature` 为 `null`；可解析但摘要无法计算时 `signedDigest` 为 `null`。
- RAW 段 `detail` 为 `{"raw": {"bytes": <storedSize>}}`；签名段为 `{"signature": {...}}`；未知类型 `detail` 为 `null`。
- 头不可解析（`F001`/坏魔数）时 `header` 为 `null`、`partitions` 为 `[]`，只输出头级 findings。
- 所有整数输出为十进制 JSON number；字节数组以小写 hex 字符串表示。
- `findings[].entryIndex`：头/表级问题为 `-1`。
- 空 findings 必须输出空数组 `[]`，不得省略字段。
