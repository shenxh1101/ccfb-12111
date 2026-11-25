"""Generate the golden sample corpus and reference JSON outputs.

Outputs:
  golden/samples/*.fw     binary firmware images (including 2 truncated ones)
  golden/expected/*.json  reference parser output, field-by-field contract
                          for the JavaScript parser
  golden/manifest.json    catalog consumed by the workbench UI

Run from repo root:  python3 -I reference/generate_samples.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fwai_format import (  # noqa: E402
    HEADER_SIZE, ENTRY_SIZE, FLAG_SIGNED, FLAG_ENCRYPTED,
    TYPE_RAW, TYPE_LZ, TYPE_SIGNATURE,
    crc32, lz_encode, make_entry, make_signature, pack, parse_firmware,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(ROOT, "golden", "samples")
EXPECTED_DIR = os.path.join(ROOT, "golden", "expected")

# (id, display name, description, tags)
CATALOG = [
    ("01-valid-basic", "最小合法包", "单 RAW 段，全部校验通过", ["valid", "raw"]),
    ("02-valid-lz-signed", "LZ 多段签名包", "两个 LZ 段 + 完整签名段", ["valid", "lz", "signed"]),
    ("03-truncated-header", "截断-文件头", "只有 10 字节，F001，禁止崩溃", ["truncated", "malformed"]),
    ("04-bad-magic", "坏魔数", "前 4 字节被破坏，F003", ["malformed"]),
    ("05-bad-header-crc", "头 CRC 损坏+保留位+加密位", "F002/F016/F019", ["crc", "flags"]),
    ("06-entry-oob", "段越界", "表项指向文件外，F005", ["oob"]),
    ("07-partial-truncated", "截断-段半切", "LZ 段尾部被切掉，F005/F006", ["truncated", "lz"]),
    ("08-overlap", "分区重叠+混合问题", "F012 重叠，外加 F010/F011/F013", ["overlap", "mixed"]),
    ("09-lz-truncated", "LZ 流提前结束", "压缩流完整但 rawSize 虚高，F006", ["lz", "malformed"]),
    ("10-lz-invalid-token", "LZ 非法 token", "输出为空即出现回溯匹配，F007", ["lz", "malformed"]),
    ("11-bomb-ratio", "解压炸弹-声明比率", "rawSize/storedSize 超 100 倍，F014", ["bomb", "lz"]),
    ("12-bomb-hardcap", "解压炸弹-硬上限(大文件)", "RLE 流可展开超 16 MiB，F014 硬截断，~12MB 压测样本", ["bomb", "lz", "large"]),
    ("13-sig-short", "签名过短", "sigLength=16，F015", ["signature"]),
    ("14-sig-malformed", "签名段结构不足", "storedSize 小于 4+sigLength+32，纯 F008", ["signature", "malformed"]),
    ("15-sig-long-badalg", "多签名+过长+未知算法", "F017/F009/F018", ["signature"]),
    ("16-mixed-findings", "分区表越界", "头中表偏移指向 EOF 之外，纯 F004", ["malformed", "table"]),
]


def layout(entries, table_off=HEADER_SIZE):
    """Fill each entry's offset: table first, segments packed after it."""
    cursor = table_off + ENTRY_SIZE * len(entries)
    for e in entries:
        e["offset"] = cursor
        cursor += e["storedSize"]
    return entries


def build_01():
    raw = b"bootloader v1.0 " * 24
    e = make_entry("boot", TYPE_RAW, 0, raw)
    return pack(layout([e]))


def build_02():
    text = (b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 16)
    data = bytes((i * 7 + 3) & 0xFF for i in range(4096))
    lz1 = lz_encode(text)
    lz2 = lz_encode(data)
    sig = make_signature(bytes(range(32)))
    entries = [
        make_entry("rootfs", TYPE_LZ, 0, lz1, raw_size=len(text)),
        make_entry("config", TYPE_LZ, 0, lz2, raw_size=len(data)),
        make_entry("signature", TYPE_SIGNATURE, 0, sig),
    ]
    return pack(layout(entries), flags=FLAG_SIGNED)


def build_03():
    return bytearray(b"FWAI\x01\x00\x10\x00\x00")  # 10 bytes only


def build_04():
    blob = build_01()
    blob[0:4] = b"XXXX"
    return blob


def build_05():
    raw = b"secure partition " * 16
    e = make_entry("secure", TYPE_RAW, 0, raw)
    # header CRC deliberately wrong; reserved header bytes polluted; encrypted
    return pack(layout([e]), flags=FLAG_ENCRYPTED,
                header_reserved=b"\xAA" + b"\x00" * 7,
                header_crc_override=0xDEADBEEF)


def build_06():
    raw = b"orphan data" * 4
    e = make_entry("ghost", TYPE_RAW, 0, raw)
    entries = layout([e])
    blob = pack(entries)
    # point the entry far beyond EOF
    import struct
    off = HEADER_SIZE + 18
    blob[off:off + 4] = struct.pack("<I", len(blob) + 0x1000)
    return blob


def build_07():
    # A segment whose tail is cut but whose header + full partition table
    # stay readable: truncate at 16 bytes inside the LZ segment. The parser
    # must keep going (no crash), report F005 + F006 and keep partial state.
    text = b"repeatable text content " * 40
    comp = lz_encode(text)
    e = make_entry("halfseg", TYPE_LZ, 0, comp, raw_size=len(text))
    entries = layout([e])
    blob = pack(entries)
    cut = e["offset"] + 16
    assert cut > HEADER_SIZE + ENTRY_SIZE
    return blob[:cut]


def build_08():
    text = b"overlapping content stream " * 24
    comp = lz_encode(text)
    lz = make_entry("rootfs", TYPE_LZ, 0, comp, raw_size=len(text))
    bad_raw = make_entry("data", TYPE_RAW, 0, b"D" * 128,
                         raw_size=256)                  # F010
    unknown = make_entry("mystery", 9, 0, b"Y" * 32)    # F011
    entries = layout([lz, bad_raw, unknown])
    # force the RAW segment 48 bytes inside the LZ segment -> F012
    bad_raw["offset"] = lz["offset"] + lz["storedSize"] - 48
    blob = bytearray(pack(entries))
    blob[lz["offset"] + 3] ^= 0xFF                      # F013
    return blob


def build_09():
    text = b"stream that ends early " * 8
    comp = lz_encode(text)
    # stream is intact but declared rawSize is 200 bytes larger
    e = make_entry("inflated", TYPE_LZ, 0, comp,
                   raw_size=len(text) + 200)
    return pack(layout([e]))


def build_10():
    # control byte 0x00 => first token is a match with empty output -> F007
    stream = b"\x00\x05\x00"
    e = make_entry("badlz", TYPE_LZ, 0, stream, raw_size=16)
    return pack(layout([e]))


def build_11():
    # Declared-ratio bomb: a small intact stream with rawSize=2 MiB gives a
    # ratio of several hundred with rawSize > 1 MiB -> F014; the short stream
    # also ends before rawSize -> F006.
    stream = lz_encode(b"padding " * 512)          # ~4 KiB class
    e = make_entry("zipbomb", TYPE_LZ, 0, stream, raw_size=2 * 1024 * 1024)
    return pack(layout([e]))


def build_12():
    # Hard-cap bomb.  One literal 'A' followed by raw16=0 match tokens:
    # with output length cur>=1 each such token means distance=1, length=3
    # (RLE-style copy).  ~5.9 M tokens are needed to cross the 16 MiB hard
    # cap; the stored stream is ~11.8 MiB which also serves as the workbench's
    # large-file / chunked-processing performance sample.
    raw_size = 17 * 1024 * 1024
    tokens_needed = (raw_size + 2) // 3
    stream = b"\x01A" + b"\x00\x00" * tokens_needed
    e = make_entry("rlebomb", TYPE_LZ, 0, stream, raw_size=raw_size)
    return pack(layout([e]))


def build_13():
    body = make_signature(b"\x11" * 16)
    e = make_entry("signature", TYPE_SIGNATURE, 0, body)
    return pack(layout([e]), flags=FLAG_SIGNED)


def build_14():
    # Pure F008: the signature bytes are fully on disk and the file is not
    # truncated, but the table entry's storedSize is smaller than the
    # 4 + sigLength + 32 structure needs. CRC is recomputed over the bytes
    # the entry actually covers, so no F013 accompanies it.
    import struct
    good = make_signature(b"\x22" * 40)
    declared = 20                       # < 4 + 40 + 32 = 76
    e = make_entry("signature", TYPE_SIGNATURE, 0, good[:declared],
                   raw_size=declared)
    entries = layout([e])
    blob = bytearray(pack(entries, flags=FLAG_SIGNED))
    # realign: keep the unused tail bytes on disk but outside the entry, so
    # no F005 fires and the file itself is well-formed
    return blob


def build_15():
    # Second signature entry -> F017; the second one also carries an
    # over-long signature (F009) and an unknown algorithm (F018).
    sig1 = make_signature(b"\x33" * 32, algorithm=1)
    sig2 = make_signature(b"\x44" * 520, algorithm=7)
    e1 = make_entry("sig1", TYPE_SIGNATURE, 0, sig1)
    e2 = make_entry("sig2", TYPE_SIGNATURE, 0, sig2)
    return pack(layout([e1, e2]), flags=FLAG_SIGNED)


def build_16():
    # Pure table-out-of-bounds case: a well-formed image whose header is then
    # patched to point the partition table beyond EOF -> F004 only.
    raw = b"table beyond eof " * 16
    e = make_entry("boot", TYPE_RAW, 0, raw)
    entries = layout([e])
    blob = bytearray(pack(entries))
    import struct
    blob[12:16] = struct.pack("<I", len(blob) + 256)
    return blob


BUILDERS = [
    build_01, build_02, build_03, build_04, build_05, build_06, build_07,
    build_08, build_09, build_10, build_11, build_12, build_13, build_14,
    build_15, build_16,
]


def main() -> None:
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    os.makedirs(EXPECTED_DIR, exist_ok=True)
    manifest = []
    for (sample_id, title, desc, tags), builder in zip(CATALOG, BUILDERS):
        blob = bytes(builder())
        fw_path = os.path.join(SAMPLES_DIR, f"{sample_id}.fw")
        with open(fw_path, "wb") as f:
            f.write(blob)
        parsed = parse_firmware(blob, f"{sample_id}.fw")
        with open(os.path.join(EXPECTED_DIR, f"{sample_id}.json"), "w",
                  encoding="utf-8") as f:
            json.dump(parsed, f, indent=2, ensure_ascii=False)
            f.write("\n")
        rule_ids = sorted({f["ruleId"] for f in parsed["findings"]})
        manifest.append({
            "id": sample_id,
            "fileName": f"{sample_id}.fw",
            "title": title,
            "description": desc,
            "tags": tags,
            "size": len(blob),
            "sha256": parsed["sha256"],
            "ruleIds": rule_ids,
            "findingCount": parsed["summary"]["totalFindings"],
        })
        print(f"{sample_id:24s} {len(blob):>9d} B  rules={','.join(rule_ids) or '-'}")
    with open(os.path.join(ROOT, "golden", "manifest.json"), "w",
              encoding="utf-8") as f:
        json.dump({"schemaVersion": 1, "samples": manifest}, f,
                  indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"\nwrote {len(CATALOG)} samples -> {SAMPLES_DIR}")


if __name__ == "__main__":
    main()
