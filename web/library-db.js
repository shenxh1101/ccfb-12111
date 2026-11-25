// Sample library persistence in IndexedDB.
//
// Stores analysis results (small JSON documents) plus, separately, the raw
// firmware Blob so the user can re-run analysis without re-uploading. The
// original file never leaves the browser: this DB is the only persistence
// layer and it is origin-local.
//
// Record shape:
//   { id, fileName, size, sha256, tags: string[], ruleIds: string[],
//     result, blob, createdAt, lastAnalyzedAt, source: 'upload'|'golden' }

const DB_NAME = 'fwai-workbench';
const DB_VERSION = 1;
const STORE = 'samples';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const os = db.createObjectStore(STORE, { keyPath: 'id' });
        os.createIndex('sha256', 'sha256', { unique: false });
        os.createIndex('createdAt', 'createdAt');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx(db, mode) {
  return db.transaction(STORE, mode).objectStore(STORE);
}

function reqAsPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function idbPut(record) {
  const db = await openDb();
  try {
    await reqAsPromise(tx(db, 'readwrite').put(record));
  } finally {
    db.close();
  }
}

export async function idbGet(id) {
  const db = await openDb();
  try {
    return await reqAsPromise(tx(db, 'readonly').get(id));
  } finally {
    db.close();
  }
}

export async function idbAll() {
  const db = await openDb();
  try {
    const rows = await reqAsPromise(tx(db, 'readonly').getAll());
    return rows.sort((a, b) => b.createdAt - a.createdAt);
  } finally {
    db.close();
  }
}

export async function idbDelete(id) {
  const db = await openDb();
  try {
    await reqAsPromise(tx(db, 'readwrite').delete(id));
  } finally {
    db.close();
  }
}

export async function idbUpdateTags(id, tags) {
  const db = await openDb();
  try {
    const store = tx(db, 'readwrite');
    const rec = await reqAsPromise(store.get(id));
    if (!rec) throw new Error(`sample ${id} not found`);
    rec.tags = [...new Set(tags.map((t) => t.trim()).filter(Boolean))];
    await reqAsPromise(store.put(rec));
    return rec;
  } finally {
    db.close();
  }
}

/**
 * Filter records by tag set (record must contain ALL selected tags) and/or
 * rule ids (record must contain ANY selected rule hit).
 */
export function filterRecords(records, { tags = [], ruleIds = [] } = {}) {
  return records.filter((r) => {
    if (tags.length && !tags.every((t) => r.tags.includes(t))) return false;
    if (ruleIds.length && !ruleIds.some((id) => r.ruleIds.includes(id))) {
      return false;
    }
    return true;
  });
}

export function allTags(records) {
  const set = new Set();
  for (const r of records) for (const t of r.tags) set.add(t);
  return [...set].sort();
}

export function allRuleIds(records) {
  const set = new Set();
  for (const r of records) for (const id of r.ruleIds) set.add(id);
  return [...set].sort();
}
