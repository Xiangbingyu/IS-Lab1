// Part II (CVE-2015-3337) evidence pages -> screenshots.
// Same mechanism as Part I: real recorded output is rendered into a page and
// screenshotted, instead of photographing a terminal. No result is fabricated.
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const root = path.resolve(__dirname, '..');
const cve = path.join(root, 'vulhub-fix', 'CVE-2015-3337');
const raw = path.join(cve, 'evidence');
const shots = path.join(root, 'evidence', 'screenshots');
fs.mkdirSync(shots, { recursive: true });

const escape = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const readText = name => fs.readFileSync(path.join(raw, name), 'utf8');

(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });

  async function capture(name, title, subtitle, body) {
    const html = `<!doctype html><meta charset="utf-8"><title>${escape(title)}</title>
<style>
body{margin:0;padding:40px;background:#edf2f4;color:#182c38;font:16px/1.5 Arial}
main{max-width:1080px;margin:auto}
h1{margin:0 0 8px;font-size:29px}
p.sub{color:#48616e;margin:0 0 18px}
pre{font:13.5px/1.55 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#fff;border:1px solid #cfdae1;padding:20px;border-radius:10px}
.diff{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:8px}
.card{background:#fff;border:1px solid #cfdae1;border-radius:10px;overflow:hidden}
.card h2{margin:0;font-size:15px;padding:10px 14px;background:#dce8ee}
.bad h2{background:#f6d9d9;color:#7a1f1f}
.good h2{background:#d8ecdd;color:#1c5a2c}
.card pre{border:0;border-radius:0;margin:0;background:#fff}
.hit{color:#a01b1b;font-weight:bold}
footer{margin-top:20px;font-size:13px;color:#48616e}
</style>
<main>
<h1>${escape(title)}</h1>
<p class="sub">${escape(subtitle)}</p>
${body}
<footer>IS Lab 1 · XiangBingYu · 23320211 · Screenshot of recorded evidence, not a terminal window.</footer>
</main>`;
    fs.writeFileSync(path.join(raw, name + '.html'), html);
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.setContent(html);
    await page.screenshot({ path: path.join(shots, name + '.png'), fullPage: true });
    await page.close();
  }

  try {
    // 07 - reproduction on the vulnerable image
    await capture(
      '07-cve-reproduction',
      'CVE-2015-3337 reproduction on the vulnerable image',
      'Source: 01-reproduction-vulnerable.txt · Elasticsearch 1.4.4 + elasticsearch-head (site plugin) on 127.0.0.1:9200',
      `<pre>${escape(readText('01-reproduction-vulnerable.txt'))}</pre>`
    );

    // 09 - vulnerable vs fixed verification
    await capture(
      '09-cve-fix-verification',
      'CVE-2015-3337 verification: vulnerable (:9200) vs fixed (:9201)',
      'Source: 02-verification-fixed-vs-vulnerable.txt · same 1.4.4 image, HttpServer.java patched with the 1.4.5 fix',
      `<pre>${escape(readText('02-verification-fixed-vs-vulnerable.txt'))}</pre>`
    );

    // 10 - attack variants
    await capture(
      '10-cve-attack-variants',
      'CVE-2015-3337 attack variants',
      'Source: 03-attack-variants.txt · encoded traversal and arbitrary-file read on both images',
      `<pre>${escape(readText('03-attack-variants.txt'))}</pre>`
    );

    // 08 - root cause diff (exact upstream code, 1.4.4 vs 1.4.5)
    const vuln = [
      '// Elasticsearch 1.4.4  (vulnerable)',
      'File siteFile = new File(new File(environment.pluginsFile(), pluginName), "_site");',
      'File file = new File(siteFile, sitePath);',
      'if (!file.exists() || file.isHidden()) {',
      '    channel.sendResponse(new BytesRestResponse(NOT_FOUND));',
      '    return;',
      '}',
      '...',
      '// getAbsolutePath() keeps the literal ".." segments, so the string',
      '// still starts with the _site prefix and the check passes.',
      'if (!file.getAbsolutePath().startsWith(siteFile.getAbsolutePath())) {',
      '    channel.sendResponse(new BytesRestResponse(FORBIDDEN));   // never triggers',
      '    return;',
      '}'
    ].join('\n');
    const fixed = [
      '// Elasticsearch 1.4.5  (fixed, this patch)',
      'File siteFile = new File(new File(environment.pluginsFile(), pluginName), "_site");',
      'File file = new File(siteFile, sitePath);',
      '// normalize() resolves "." and ".." first, then the normalized path must',
      '// still stay inside _site; traversal escapes are rejected with 404.',
      'if (!file.exists() || file.isHidden()',
      '        || !file.getAbsoluteFile().toPath().normalize()',
      '                .startsWith(siteFile.getAbsoluteFile().toPath())) {',
      '    channel.sendResponse(new BytesRestResponse(NOT_FOUND));',
      '    return;',
      '}'
    ].join('\n');
    await capture(
      '08-cve-root-cause',
      'CVE-2015-3337 root cause and fix',
      'HttpServer.handlePluginSite() · exact upstream code from the 1.4.4 and 1.4.5 tags',
      `<div class="diff">
<div class="card bad"><h2>1.4.4 vulnerable — getAbsolutePath()</h2><pre>${escape(vuln)}</pre></div>
<div class="card good"><h2>1.4.5 fixed — toPath().normalize()</h2><pre>${escape(fixed)}</pre></div>
</div>
<p class="sub" style="margin-top:16px">getAbsolutePath() does not resolve <code>..</code>, so <code>/.../_site/../../etc/passwd</code> still satisfies the <code>startsWith</code> prefix test. resolve-then-compare rejects it.</p>`
    );

    console.log('Part II evidence screenshots written to', shots);
  } finally {
    await browser.close();
  }
})();
