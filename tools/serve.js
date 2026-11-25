// Zero-dependency static server for the offline workbench.
// Serves the repo root so the page at /web/index.html can reach /golden and
// /src with the same relative paths used in production packaging.
//
// Run: npm run serve  (or: node tools/serve.js [port])

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const port = Number(process.argv[2]) || 8080;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.fw': 'application/octet-stream',
  '.md': 'text/markdown; charset=utf-8',
};

createServer(async (req, res) => {
  try {
    const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    let path = normalize(join(root, urlPath === '/' ? '/web/index.html' : urlPath));
    if (!path.startsWith(root)) {
      res.writeHead(403).end('forbidden');
      return;
    }
    const info = await stat(path).catch(() => null);
    if (info?.isDirectory()) path = join(path, 'index.html');
    const data = await readFile(path);
    res.writeHead(200, {
      'Content-Type': MIME[extname(path)] ?? 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    res.end(data);
  } catch (err) {
    res.writeHead(404, { 'Content-Type': 'text/plain' }).end(`not found: ${err.message}`);
  }
}).listen(port, () => {
  console.log(`FWAI workbench: http://localhost:${port}/web/index.html`);
});
