"""FWAI firmware format reference implementation (stdlib only).

This module is the *defining* implementation of the FWAI format described in
docs/firmware-format.md.  It contains:

  * LZSS encode/decode (see format spec section 4)
  * a packer used by reference/generate_samples.py
  * a deterministic audit parser, parse_firmware(), whose JSON output is the
    golden contract that the browser-side JS parser must match field by field.

Run with: python3 -I reference/fwai_format.py   (self-test)
"""

from __future__ import annotations

import hashlib
import json
import zlib
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

MAGIC = b"FWAI"
HEADER_SIZE = 32
ENTRY_SIZE = 36
MAX_PARTITIONS = 128
LZ_WINDOW = 4096
MAX_OUTPUT = 16 * 1024 * 1024          # hard decompression cap, 16 MiB
BOMB_RATIO = 100
BOMB_RAW_GATE = 1 * 1024 * 1024        # ratio rule only above 1 MiB raw
SIG_MIN_LEN = 32
SIG_MAX_LEN = 512
SIG_PUBLIC_LEN = 32

TYPE_RAW = 1
TYPE_LZ = 2
TYPE_SIGNATURE = 3
TYPE_LABELS = {TYPE_RAW: "RAW", TYPE_LZ: "LZ", TYPE_SIGNATURE: "SIGNATURE"}

FLAG_SIGNED = 0x0001
FLAG_ENCRYPTED = 0x0002

RULES: dict[str, tuple[str, str]] = {
    # ruleId: (severity, canonical message) — message strings are part of the
    # golden contract and must be replicated verbatim in src/rules.js
    "F001": ("critical", "file truncated before end of 32-byte header"),
    "F002": ("critical", "header CRC-32 mismatch"),
    "F003": ("critical", 'bad magic: expected "FWAI"'),
    "F004": ("critical",
             "partition table extends beyond file or partition count exceeds 128"),
    "F005": ("high", "partition segment extends beyond file boundary"),
    "F006": ("high", "LZ stream ended before declared rawSize was reached"),
    "F007": ("high",
             "malformed LZ token: back-reference with empty output or token "
             "crossing segment boundary"),
    "F008": ("high",
             "signature segment shorter than 4 + sigLength + 32 bytes"),
    "F009": ("medium", "signature length exceeds 512 bytes"),
    "F010": ("low", "declared size does not match actual segment data"),
    "F011": ("info", "unknown partition entry type"),
    "F012": ("high", "partition storage intervals overlap"),
    "F013": ("medium", "partition CRC-32 mismatch"),
    "F014": ("high",
             "decompression bomb: compression ratio over 100x or output "
             "exceeded 16 MiB cap"),
    "F015": ("medium", "signature shorter than 32 bytes"),
    "F016": ("medium", "reserved field contains non-zero bytes"),
    "F017": ("medium", "more than one signature partition entry"),
    "F018": ("medium",
             "unknown signature algorithm (only algorithm 1 / HMAC-SHA256 "
             "is defined)"),
    "F019": ("low",
             "encrypted flag is set; encrypted firmware is not supported by "
             "this workbench"),
    "F020": ("low", "header fileSize does not match actual file length"),
}


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def u16(buf: bytes | bytearray, off: int) -> int:
    return int.from_bytes(buf[off:off + 2], "little")


def u32(buf: bytes | bytearray, off: int) -> int:
    return int.from_bytes(buf[off:off + 4], "little")


def crc32(buf: bytes | bytearray) -> int:
    return zlib.crc32(bytes(buf)) & 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# LZSS codec (spec section 4)
# --------------------------------------------------------------------------- #

def lz_encode(data: bytes) -> bytes:
    """Greedy LZSS encoder matching the format spec's token layout."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        ctrl_pos = len(out)
        out.append(0)
        control = 0
        for bit in range(8):
            if i >= n:
                break
            best_len = 0
            best_dist = 0
            window_start = max(0, i - LZ_WINDOW)
            for cand in range(window_start, i):
                max_len = min(n - i, 3 + (65535 - (i - cand - 1)) // max(i, 1))
                mlen = 0
                while mlen < max_len and data[cand + mlen] == data[i + mlen]:
                    mlen += 1
                if mlen >= 3 and mlen > best_len:
                    best_len = mlen
                    best_dist = i - cand
            if best_len >= 3:
                raw16 = (best_dist - 1) + (best_len - 3) * i
                out.extend(raw16.to_bytes(2, "little"))
                i += best_len  # control bit stays 0 (match)
            else:
                control |= 1 << bit
                out.append(data[i])
                i += 1
        out[ctrl_pos] = control
    return bytes(out)


@dataclass
class LzResult:
    output: bytes
    control_bytes: int
    literal_tokens: int
    match_tokens: int
    consumed: int
    error: str | None = None       # rule id of first terminating error
    bomb_hard: bool = False


def lz_decode(buf: bytes, raw_size: int) -> LzResult:
    """Decode one LZ stream. Never raises on malformed input (safe parser)."""
    out = bytearray()
    pos = 0
    n = len(buf)
    control_bytes = literal_tokens = match_tokens = 0
    error: str | None = None

    while len(out) < raw_size:
        if pos >= n:
            error = "F006"
            break
        control = buf[pos]
        pos += 1
        control_bytes += 1
        for bit in range(8):
            if len(out) >= raw_size:
                break
            if control & (1 << bit):
                # literal token
                if pos >= n:
                    error = "F006"
                    break
                out.append(buf[pos])
                pos += 1
                literal_tokens += 1
            else:
                # back-reference match token
                if pos + 2 > n:
                    error = "F007"
                    break
                if len(out) == 0:
                    error = "F007"
                    break
                raw16 = u16(buf, pos)
                pos += 2
                cur = len(out)
                distance = (raw16 % cur) + 1
                length = (raw16 // cur) + 3
                src = cur - distance
                for _ in range(length):
                    if len(out) >= raw_size:
                        break
                    if len(out) >= MAX_OUTPUT:
                        error = "F014"
                        break
                    out.append(out[src])
                    src += 1
                match_tokens += 1
                if error:
                    break
        if error or len(out) >= raw_size:
            break

    bomb_hard = error == "F014"
    return LzResult(bytes(out), control_bytes, literal_tokens,
                    match_tokens, pos, error, bomb_hard)


# --------------------------------------------------------------------------- #
# Packer
# --------------------------------------------------------------------------- #

def make_entry(name: str, entry_type: int, offset: int, stored: bytes,
               raw_size: int | None = None, crc: int | None = None,
               reserved17: int = 0, reserved34: bytes = b"\x00\x00") -> dict:
    if raw_size is None:
        raw_size = len(stored)
    if crc is None:
        crc = crc32(stored)
    return {
        "name": name, "type": entry_type, "offset": offset,
        "stored": stored, "storedSize": len(stored), "rawSize": raw_size,
        "crc": crc, "reserved17": reserved17, "reserved34": reserved34,
    }


def pack(entries: list[dict], flags: int = 0,
         table_offset: int = HEADER_SIZE,
         header_reserved: bytes = b"\x00" * 8,
         file_size_override: int | None = None,
         header_crc_override: int | None = None,
         count_override: int | None = None) -> bytearray:
    """Assemble a firmware image from entries with precomputed offsets."""
    total = max((e["offset"] + e["storedSize"] for e in entries),
                default=table_offset)
    total = max(total, table_offset + ENTRY_SIZE * len(entries))
    blob = bytearray(total)
    for e in entries:
        blob[e["offset"]:e["offset"] + e["storedSize"]] = e["stored"]
    count = count_override if count_override is not None else len(entries)
    # header. Fill every field first, zero the CRC field, and only then take
    # the CRC over bytes [0,28): the CRC must describe the final on-disk
    # header content with its own field present as zeroes.
    declared_size = total if file_size_override is None else file_size_override
    blob[0:4] = MAGIC
    blob[4:6] = (1).to_bytes(2, "little")
    blob[6:8] = HEADER_SIZE.to_bytes(2, "little")
    blob[8:12] = declared_size.to_bytes(4, "little")
    blob[12:16] = table_offset.to_bytes(4, "little")
    blob[16:18] = count.to_bytes(2, "little")
    blob[18:20] = flags.to_bytes(2, "little")
    blob[20:24] = b"\x00\x00\x00\x00"
    blob[24:32] = header_reserved
    hcrc = header_crc_override if header_crc_override is not None \
        else crc32(blob[0:28])
    blob[20:24] = hcrc.to_bytes(4, "little")
    # partition table
    for idx, e in enumerate(entries):
        b = table_offset + idx * ENTRY_SIZE
        nm = e["name"].encode("ascii")[:16]
        blob[b:b + 16] = nm.ljust(16, b"\x00")
        blob[b + 16] = e["type"]
        blob[b + 17] = e.get("reserved17", 0)
        blob[b + 18:b + 22] = e["offset"].to_bytes(4, "little")
        blob[b + 22:b + 26] = e["storedSize"].to_bytes(4, "little")
        blob[b + 26:b + 30] = e["rawSize"].to_bytes(4, "little")
        blob[b + 30:b + 34] = e["crc"].to_bytes(4, "little")
        blob[b + 34:b + 36] = e.get("reserved34", b"\x00\x00")
    return blob


def make_signature(sig: bytes, algorithm: int = 1,
                   public_data: bytes | None = None) -> bytes:
    if public_data is None:
        public_data = bytes(range(32))
    return (algorithm.to_bytes(2, "little")
            + len(sig).to_bytes(2, "little") + sig + public_data)


# --------------------------------------------------------------------------- #
# Audit parser
# --------------------------------------------------------------------------- #

class _Builder:
    def __init__(self) -> None:
        self.findings: list[dict] = []

    def add(self, rule_id: str, offset: int, entry_index: int) -> None:
        sev, msg = RULES[rule_id]
        self.findings.append({
            "ruleId": rule_id, "severity": sev, "offset": offset,
            "entryIndex": entry_index, "message": msg,
        })


def parse_firmware(data: bytes, file_name: str) -> dict[str, Any]:
    b = _Builder()
    size = len(data)
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "fileName": file_name,
        "fileSize": size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "header": None,
        "partitions": [],
        "findings": [],
        "signature": None,
        "summary": {},
    }

    # ---- stage 1: header -------------------------------------------------- #
    if size < HEADER_SIZE:
        b.add("F001", 0, -1)
        return _finalize(result, b)
    if data[0:4] != MAGIC:
        b.add("F003", 0, -1)
        return _finalize(result, b)

    header = {
        "magic": "FWAI",
        "headerVersion": u16(data, 4),
        "headerSize": u16(data, 6),
        "fileSize": u32(data, 8),
        "partitionTableOffset": u32(data, 12),
        "partitionCount": u16(data, 16),
        "flags": u16(data, 18),
        "headerCrc32": u32(data, 20),
        "reserved": data[24:32].hex(),
    }
    result["header"] = header

    # The CRC field at [20,24) lies inside the covered range [0,28), so the
    # field must be treated as zeroes on verification as well (the writer
    # computed it over a zeroed field).
    header_for_crc = bytearray(data[0:28])
    header_for_crc[20:24] = b"\x00\x00\x00\x00"
    if crc32(header_for_crc) != header["headerCrc32"]:
        b.add("F002", 20, -1)
    if any(x != 0 for x in data[24:32]):
        b.add("F016", 24, -1)
    if header["flags"] & FLAG_ENCRYPTED:
        b.add("F019", 18, -1)
    if header["flags"] & ~0x0003:
        b.add("F016", 18, -1)
    if header["fileSize"] != size:
        b.add("F020", 8, -1)

    table_offset = header["partitionTableOffset"]
    count = header["partitionCount"]
    table_end = table_offset + ENTRY_SIZE * count
    table_unreadable = (count > MAX_PARTITIONS or table_end > size
                        or table_end > 0xFFFFFFFF or table_offset > size)
    if table_unreadable:
        b.add("F004", 16 if count > MAX_PARTITIONS else 12, -1)

    # ---- stage 2: partition table ---------------------------------------- #
    raw_entries: list[dict] = []
    if not table_unreadable:
        readable = count
    else:
        readable = 0
        if count <= MAX_PARTITIONS and table_offset <= size:
            readable = min(count, (size - table_offset) // ENTRY_SIZE)
    for idx in range(readable):
        bp = table_offset + idx * ENTRY_SIZE
        if any(x != 0 for x in data[bp + 17:bp + 18]):
            b.add("F016", bp + 17, idx)
        if any(x != 0 for x in data[bp + 34:bp + 36]):
            b.add("F016", bp + 34, idx)
        raw_entries.append({
            "entryIndex": idx,
            "name": data[bp:bp + 16].split(b"\x00", 1)[0].decode(
                "ascii", "replace"),
            "entryType": data[bp + 16],
            "entryOffset": u32(data, bp + 18),
            "storedSize": u32(data, bp + 22),
            "rawSize": u32(data, bp + 26),
            "entryCrc32": u32(data, bp + 30),
            "_tableOffset": bp,
        })

    # ---- stage 3: per-segment checks ------------------------------------- #
    sig_seen = 0
    for e in raw_entries:
        idx = e["entryIndex"]
        start = e["entryOffset"]
        stored = e["storedSize"]
        end = start + stored
        unparseable = start > size or end > 0xFFFFFFFF
        truncated = False
        if not unparseable and end > size:
            truncated = True
            b.add("F005", start, idx)
        if unparseable:
            b.add("F005", start, idx)
            result["partitions"].append(_partition_row(
                e, crc_valid=None, truncated=False, unparseable=True,
                detail=None))
            continue

        avail = data[start:min(end, size)]
        crc_valid = crc32(avail) == e["entryCrc32"]
        if not crc_valid:
            b.add("F013", start, idx)

        detail: Any = None
        etype = e["entryType"]
        if etype == TYPE_RAW:
            if e["rawSize"] != stored:
                b.add("F010", start, idx)
            detail = {"raw": {"bytes": stored}}
        elif etype == TYPE_LZ:
            detail = _audit_lz(e, avail, truncated, b, idx)
        elif etype == TYPE_SIGNATURE:
            detail = _audit_signature(e, avail, b, idx, sig_seen)
            sig_seen += 1
            if sig_seen >= 2:
                b.add("F017", start, idx)
        else:
            b.add("F011", e["_tableOffset"] + 16, idx)
            detail = None

        result["partitions"].append(_partition_row(
            e, crc_valid, truncated, False, detail))

    # ---- stage 4: global checks ------------------------------------------ #
    intervals = [(e["entryIndex"], e["entryOffset"],
                  e["entryOffset"] + e["storedSize"])
                 for e in raw_entries
                 if e["entryOffset"] <= size
                 and e["entryOffset"] + e["storedSize"] <= 0xFFFFFFFF
                 and not any(p["entryIndex"] == e["entryIndex"]
                             and p["unparseable"]
                             for p in result["partitions"])]
    for k in range(len(intervals)):
        i_idx, i_start, i_end = intervals[k]
        for j in range(k + 1, len(intervals)):
            j_idx, j_start, j_end = intervals[j]
            if i_start < j_end and j_start < i_end:
                b.add("F012", j_start, j_idx)

    result["signature"] = _build_signature_summary(raw_entries, data, result)

    return _finalize(result, b)


def _audit_lz(e: dict, avail: bytes, truncated: bool,
              b: _Builder, idx: int) -> dict:
    raw_size = e["rawSize"]
    if (raw_size > BOMB_RAW_GATE
            and raw_size // max(e["storedSize"], 1) > BOMB_RATIO):
        b.add("F014", e["entryOffset"], idx)
    dec = lz_decode(avail, raw_size)
    if dec.error == "F014":
        b.add("F014", e["entryOffset"], idx)
    elif dec.error == "F007":
        b.add("F007", e["entryOffset"], idx)
    elif dec.error == "F006":
        b.add("F006", e["entryOffset"], idx)
    if dec.error is None and dec.consumed < len(avail):
        b.add("F010", e["entryOffset"], idx)
    return {"lz": {
        "controlBytes": dec.control_bytes,
        "literalTokens": dec.literal_tokens,
        "matchTokens": dec.match_tokens,
        "consumed": dec.consumed,
        "decompressedSize": len(dec.output),
    }}


def _audit_signature(e: dict, avail: bytes, b: _Builder,
                     idx: int, sig_seen: int) -> dict:
    start = e["entryOffset"]
    algo: int | None = None
    sig_len: int | None = None
    public_hex: str | None = None
    if len(avail) >= 4:
        algo = u16(avail, 0)
        sig_len = u16(avail, 2)
        if sig_len < SIG_MIN_LEN:
            b.add("F015", start + 2, idx)
        if sig_len > SIG_MAX_LEN:
            b.add("F009", start + 2, idx)
        if algo != 1:
            b.add("F018", start, idx)
        if len(avail) >= 4 + sig_len + SIG_PUBLIC_LEN:
            public_hex = avail[4 + sig_len:4 + sig_len + SIG_PUBLIC_LEN].hex()
        else:
            b.add("F008", start, idx)
    else:
        b.add("F008", start, idx)
    return {"signature": {
        "algorithm": algo,
        "sigLength": sig_len,
        "publicData": public_hex,
    }}


def _build_signature_summary(raw_entries: list[dict], data: bytes,
                             result: dict) -> dict | None:
    sig_entries = [e for e in raw_entries if e["entryType"] == TYPE_SIGNATURE]
    if not sig_entries:
        return None
    e = sig_entries[0]
    start, stored = e["entryOffset"], e["storedSize"]
    if start > len(data) or start + stored > 0xFFFFFFFF:
        return None
    avail = data[start:min(start + stored, len(data))]
    row = next((p for p in result["partitions"]
                if p["entryIndex"] == e["entryIndex"]), None)
    malformed = row is not None and any(
        f["ruleId"] == "F008" and f["entryIndex"] == e["entryIndex"]
        for f in result["findings"])
    truncated = row is not None and row["truncated"]
    algo = u16(avail, 0) if len(avail) >= 2 else None
    sig_len = u16(avail, 2) if len(avail) >= 4 else None
    public_hex = None
    digest = None
    if sig_len is not None and len(avail) >= 4 + sig_len + SIG_PUBLIC_LEN:
        public_hex = avail[4 + sig_len:4 + sig_len + SIG_PUBLIC_LEN].hex()
    if not malformed and not truncated and public_hex is not None:
        digest = _compute_signed_digest(raw_entries, data, e, result)
    return {
        "present": True,
        "entryIndex": e["entryIndex"],
        "algorithm": algo,
        "sigLength": sig_len,
        "publicData": public_hex,
        "signedDigest": digest,
    }


def _compute_signed_digest(raw_entries: list[dict], data: bytes,
                           sig_entry: dict, result: dict) -> str | None:
    h = hashlib.sha256()
    h.update(data[0:HEADER_SIZE])
    table_off = u32(data, 12)
    count = u16(data, 16)
    h.update(data[table_off:table_off + ENTRY_SIZE * count])
    rows = {p["entryIndex"]: p for p in result["partitions"]}
    for e in raw_entries:
        if e["entryIndex"] == sig_entry["entryIndex"]:
            continue
        row = rows.get(e["entryIndex"])
        if row is None or row["truncated"] or row["unparseable"]:
            return None
        start, end = e["entryOffset"], e["entryOffset"] + e["storedSize"]
        h.update(data[start:end])
    return h.hexdigest()


def _partition_row(e: dict, crc_valid: bool | None, truncated: bool,
                   unparseable: bool, detail: Any) -> dict:
    return {
        "entryIndex": e["entryIndex"],
        "name": e["name"],
        "entryType": e["entryType"],
        "entryTypeLabel": TYPE_LABELS.get(e["entryType"], "UNKNOWN"),
        "entryOffset": e["entryOffset"],
        "storedSize": e["storedSize"],
        "rawSize": e["rawSize"],
        "entryCrc32": e["entryCrc32"],
        "crcValid": crc_valid,
        "truncated": truncated,
        "unparseable": unparseable,
        "detail": detail,
    }


def _finalize(result: dict, b: _Builder) -> dict:
    b.findings.sort(key=lambda f: (f["offset"], f["ruleId"], f["entryIndex"]))
    result["findings"] = b.findings
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in b.findings:
        counts[f["severity"]] += 1
    result["summary"] = {
        "findingCounts": counts,
        "totalFindings": len(b.findings),
        "partitionsTotal": len(result["partitions"]),
        "partitionsTruncated": sum(1 for p in result["partitions"]
                                   if p["truncated"]),
        "partitionsUnparseable": sum(1 for p in result["partitions"]
                                     if p["unparseable"]),
    }
    return result


def parse_to_json(data: bytes, file_name: str) -> str:
    return json.dumps(parse_firmware(data, file_name), indent=2,
                      ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    payload = (b"The quick brown fox jumps over the lazy dog. " * 8)
    comp = lz_encode(payload)
    dec = lz_decode(comp, len(payload))
    assert dec.error is None and dec.output == payload, "LZ round-trip failed"
    # control 0x03 = two literal bits: exact-size decode, clean finish
    ok = lz_decode(b"\x03AB", 2)
    assert ok.error is None and ok.output == b"AB" and ok.consumed == 3
    # same stream, larger rawSize: unused zero bits become match reads past
    # the segment boundary -> F007
    assert lz_decode(b"\x03AB", 5).error == "F007"
    # 8 literal bits requested, only 2 bytes present -> F006 mid-block
    assert lz_decode(b"\xFF\x41", 4).error == "F006"
    # control 0x01: one literal then a match token crossing the boundary
    assert lz_decode(b"\x01A\x00", 4).error == "F007"
    # match token with empty output -> F007
    assert lz_decode(b"\x00\x00\x00", 4).error == "F007"
    print("lz self-test OK:", len(payload), "->", len(comp), "bytes")
