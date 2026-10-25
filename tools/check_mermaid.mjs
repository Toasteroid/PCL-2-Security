// 用真实浏览器中的 mermaid 解析每个图块，输出通过/失败与错误原文。
// 用法: node check.mjs <md文件> [mermaid版本目录]
import fs from 'fs';
import http from 'http';
import path from 'path';
import { createRequire } from 'module';
import puppeteer from 'puppeteer-core';

const mdPath = process.argv[2];
const md = fs.readFileSync(mdPath, 'utf8');

// 抽取 mermaid 代码块
const blocks = [];
const lines = md.split('\n');
for (let i = 0; i < lines.length; i++) {
  if (lines[i].trim().startsWith('```mermaid')) {
    const start = i + 1;
    let j = start;
    while (j < lines.length && !lines[j].trim().startsWith('```')) j++;
    blocks.push({ line: start, text: lines.slice(start, j).join('\n') });
    i = j;
  }
}

const root = 'C:/Users/DELL';
const server = http.createServer((req, res) => {
  const u = decodeURIComponent(req.url.split('?')[0]);
  if (u === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html><meta charset="utf-8"><div id="c"></div>
<script type="module">
import mermaid from '/node_modules/mermaid/dist/mermaid.esm.mjs';
mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });
window.__mermaid = mermaid;
window.__ready = true;
</script>`);
    return;
  }
  const p = path.join(root, u);
  if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) { res.writeHead(404); res.end('no'); return; }
  const ext = path.extname(p);
  const type = ext === '.mjs' || ext === '.js' ? 'text/javascript' : ext === '.css' ? 'text/css' : 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': type });
  fs.createReadStream(p).pipe(res);
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const port = server.address().port;

const exe = process.env.CHROME_PATH;
const browser = await puppeteer.launch({
  executablePath: exe,
  headless: true,
  args: ['--no-sandbox', '--disable-gpu'],
});
const page = await browser.newPage();
await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'networkidle0' });
await page.waitForFunction('window.__ready === true', { timeout: 30000 });
const version = await page.evaluate('window.__mermaidVersion || (window.__mermaid && "loaded")');

let ok = 0, bad = 0;
const fails = [];
for (let k = 0; k < blocks.length; k++) {
  const r = await page.evaluate(async (txt) => {
    try {
      await window.__mermaid.parse(txt);
      return { ok: true };
    } catch (e) {
      return { ok: false, msg: String(e && e.message || e) };
    }
  }, blocks[k].text);
  if (r.ok) ok++;
  else { bad++; fails.push({ idx: k + 1, line: blocks[k].line, msg: r.msg }); }
}
// 附加实验：把换行全部吃掉，验证分号兜底
let joinedOk = 0;
for (let k = 0; k < blocks.length; k++) {
  const joined = blocks[k].text.split('\n').map(s => s.trim()).filter(Boolean).join('');
  const r = await page.evaluate(async (txt) => {
    try { await window.__mermaid.parse(txt); return true; } catch (e) { return false; }
  }, joined);
  if (r) joinedOk++;
}
await browser.close();
server.close();
console.log(`version=${version} blocks=${blocks.length} pass=${ok} fail=${bad} joinedLinePass=${joinedOk}`);
for (const f of fails) console.log(`FAIL #${f.idx} (line ${f.line}): ${f.msg.split('\n').slice(0, 4).join(' | ')}`);
