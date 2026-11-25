// Audit rule catalog — mirrors docs/audit-rules.md and reference/fwai_format.py
// RULES. Message strings are part of the golden contract: keep them byte-for-byte
// identical to the Python reference.

export const RULES = {
  F001: ['critical', 'file truncated before end of 32-byte header'],
  F002: ['critical', 'header CRC-32 mismatch'],
  F003: ['critical', 'bad magic: expected "FWAI"'],
  F004: ['critical', 'partition table extends beyond file or partition count exceeds 128'],
  F005: ['high', 'partition segment extends beyond file boundary'],
  F006: ['high', 'LZ stream ended before declared rawSize was reached'],
  F007: ['high', 'malformed LZ token: back-reference with empty output or token crossing segment boundary'],
  F008: ['high', 'signature segment shorter than 4 + sigLength + 32 bytes'],
  F009: ['medium', 'signature length exceeds 512 bytes'],
  F010: ['low', 'declared size does not match actual segment data'],
  F011: ['info', 'unknown partition entry type'],
  F012: ['high', 'partition storage intervals overlap'],
  F013: ['medium', 'partition CRC-32 mismatch'],
  F014: ['high', 'decompression bomb: compression ratio over 100x or output exceeded 16 MiB cap'],
  F015: ['medium', 'signature shorter than 32 bytes'],
  F016: ['medium', 'reserved field contains non-zero bytes'],
  F017: ['medium', 'more than one signature partition entry'],
  F018: ['medium', 'unknown signature algorithm (only algorithm 1 / HMAC-SHA256 is defined)'],
  F019: ['low', 'encrypted flag is set; encrypted firmware is not supported by this workbench'],
  F020: ['low', 'header fileSize does not match actual file length'],
};

export const HEADER_SIZE = 32;
export const ENTRY_SIZE = 36;
export const MAX_PARTITIONS = 128;
export const MAX_OUTPUT = 16 * 1024 * 1024;
export const BOMB_RATIO = 100;
export const BOMB_RAW_GATE = 1024 * 1024;
export const SIG_MIN_LEN = 32;
export const SIG_MAX_LEN = 512;
export const SIG_PUBLIC_LEN = 32;

export const TYPE_RAW = 1;
export const TYPE_LZ = 2;
export const TYPE_SIGNATURE = 3;
export const TYPE_LABELS = { 1: 'RAW', 2: 'LZ', 3: 'SIGNATURE' };

export const FLAG_SIGNED = 0x0001;
export const FLAG_ENCRYPTED = 0x0002;
