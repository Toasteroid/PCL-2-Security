// 用浏览器 + mermaid 默认配置渲染指定图块为 PNG，便于肉眼检查断行/截断。
// 用法: node render.mjs <md文件> <输出目录> <块号,逗号分隔|all>
import fs from 'fs';
import http from 'http';
import path from 'path';
import puppeteer from 'puppeteer-core';

const mdPath = process.argv[2];
const outDir = process.argv[3];
const which = process.argv[4] || 'all';
fs.mkdirSync(outDir, { recursive: true });

const md = fs.readFileSync(mdPath, 'utf8');
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
    res.end(`<!doctype html><meta charset="utf-8">
<style>body{margin:0;background:#fff}#c{padding:8px;display:inline-block}</style>
<div id="c"></div>
<script type="module">
import mermaid from '/node_modules/mermaid/dist/mermaid.esm.mjs';
mermaid.initialize({ startOnLoad: false });
window.__m = mermaid;
window.__ready = true;
</script>`);
    return;
  }
  const p = path.join(root, u);
  if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) { res.writeHead(404); res.end('no'); return; }
  const ext = path.extname(p);
  const type = ['.mjs', '.js'].includes(ext) ? 'text/javascript' : ext === '.css' ? 'text/css' : 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': type });
  fs.createReadStream(p).pipe(res);
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const port = server.address().port;

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME_PATH,
  headless: true,
  args: ['--no-sandbox', '--disable-gpu'],
});
const page = await browser.newPage();
await page.setViewport({ width: 900, height: 1200, deviceScaleFactor: 1.6 });
await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'networkidle0' });
await page.waitForFunction('window.__ready === true');

const idxs = which === 'all' ? blocks.map((_, i) => i) : which.split(',').map(s => Number(s) - 1);
for (const k of idxs) {
  const r = await page.evaluate(async (txt) => {
    const el = document.getElementById('c');
    el.innerHTML = '';
    try {
      const { svg } = await window.__m.render('g' + Math.random().toString(36).slice(2), txt);
      el.innerHTML = svg;
      const svgEl = el.querySelector('svg');
      // 按图自身尺寸渲染，避免 max-width:100% 把宽图压扁
      const vb = svgEl.viewBox && svgEl.viewBox.baseVal;
      if (vb && vb.width) {
        svgEl.style.maxWidth = 'none';
        svgEl.style.width = vb.width + 'px';
        svgEl.style.height = vb.height + 'px';
        svgEl.setAttribute('width', vb.width);
        svgEl.setAttribute('height', vb.height);
      }
      return { ok: true };
    } catch (e) {
      return { ok: false, msg: String(e) };
    }
  }, blocks[k].text);
  if (!r.ok) { console.log(`#${k + 1} RENDER FAIL: ${r.msg.split('\n')[0]}`); continue; }
  const el = await page.$('#c');
  const name = `b${String(k + 1).padStart(2, '0')}.png`;
  await el.screenshot({ path: path.join(outDir, name) });
  const box = await el.boundingBox();
  console.log(`#${k + 1} ok ${Math.round(box.width)}x${Math.round(box.height)} -> ${name}`);
}
await browser.close();
server.close();
