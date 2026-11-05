// Real browser checks and screenshots. Install Playwright separately to rerun.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname, '..');
const raw = path.join(root, 'evidence', 'raw');
const shots = path.join(root, 'evidence', 'screenshots');
fs.mkdirSync(shots, { recursive: true });
const credentials = JSON.parse(fs.readFileSync(path.join(root, 'evidence/private/demo-login.json'), 'utf8'));
const escape = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function evidencePage(browser, filename, title, subtitle, text) {
  const html = `<!doctype html><meta charset="utf-8"><title>${escape(title)}</title><style>body{font:16px Arial;background:#edf2f4;color:#182c38;margin:0;padding:44px}main{max-width:1080px;margin:auto}h1{font-size:30px}p{color:#48616e}pre{font:14px/1.6 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:white;border:1px solid #cfdae1;padding:24px;border-radius:10px}</style><main><h1>${escape(title)}</h1><p>${escape(subtitle)}</p><pre>${escape(text)}</pre></main>`;
  fs.writeFileSync(path.join(raw, filename + '.html'), html);
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.setContent(html);
  await page.screenshot({ path: path.join(shots, filename + '.png'), fullPage: true });
  await page.close();
}
(async () => {
  const browser = await chromium.launch({ channel: process.env.BROWSER_CHANNEL || 'chrome', headless: true });
  try {
    const context = await browser.newContext({ viewport: {width:1280,height:1100} });
    const page = await context.newPage();
    const dialogs = [];
    page.on('dialog', async dialog => { dialogs.push(dialog.message()); await dialog.dismiss(); });
    await page.goto('http://127.0.0.1:5081');
    await page.locator('[name=username]').fill(credentials.username);
    await page.locator('[name=password]').fill(credentials.password);
    await page.getByRole('button', {name:'Sign in',exact:true}).click();
    await page.getByText('Signed in as student', {exact:false}).waitFor();
    await page.locator('[name=title]').fill('Security lifecycle');
    await page.locator('[name=body]').fill('Build the API, test its protections, audit dependencies, and verify the results.');
    await page.getByRole('button', {name:'Save note'}).click();
    await page.locator('article').filter({hasText:'Security lifecycle'}).waitFor();
    await page.screenshot({path:path.join(shots,'01-notes-working.png'),fullPage:true});
    const payload = "<script>window.__xss=1;alert('xss')</script><img src=x onerror=\"window.__xss=1\">";
    await page.locator('[name=title]').fill('XSS payload displayed as text');
    await page.locator('[name=body]').fill(payload);
    await page.getByRole('button', {name:'Save note'}).click();
    await page.locator('article p').filter({hasText:payload}).waitFor();
    assert.equal(await page.locator('#notes script,#notes img').count(),0);
    assert.equal(await page.evaluate(() => window.__xss),undefined);
    assert.equal(dialogs.length,0);
    await page.screenshot({path:path.join(shots,'02-xss-safe-rendering.png'),fullPage:true});
    // Disable CSP in a second context to prove the safe DOM sink independently.
    const noCsp = await browser.newContext({bypassCSP:true});
    const second = await noCsp.newPage();
    second.on('dialog', async dialog => { dialogs.push(dialog.message()); await dialog.dismiss(); });
    await second.goto('http://127.0.0.1:5081');
    await second.locator('[name=username]').fill(credentials.username);
    await second.locator('[name=password]').fill(credentials.password);
    await second.getByRole('button',{name:'Sign in',exact:true}).click();
    await second.locator('article p').filter({hasText:payload}).waitFor();
    assert.equal(await second.locator('#notes script,#notes img').count(),0);
    assert.equal(await second.evaluate(() => window.__xss),undefined);
    assert.equal(dialogs.length,0);
    await noCsp.close();
    const api = context.request;
    const base = 'http://127.0.0.1:5081';
    const login = await api.post(base+'/auth/login',{data:credentials});
    assert.equal(login.status(),200);
    const token = (await login.json()).access_token;
    const headers = {Authorization:`Bearer ${token}`};
    const checks = [];
    async function record(name, response, expected) {
      const data = await response.json();
      assert.equal(response.status(),expected);
      checks.push({name,status:response.status(),body:data});
      return data;
    }
    await record('GET /health',await api.get(base+'/health'),200);
    await record('GET /api/data without token',await api.get(base+'/api/data'),401);
    await record('POST /auth/login with SQL injection username',await api.post(base+'/auth/login',{data:{username:"' OR '1'='1' --",password:'invalid-demo'}}),401);
    const search = await record('GET /api/notes?q=SQL-injection-payload',await api.get(base+'/api/notes',{headers,params:{q:"' OR '1'='1' --"}}),200);
    assert.deepEqual(search.notes,[]);
    await record('GET /api/data with tampered token',await api.get(base+'/api/data',{headers:{Authorization:`Bearer ${token.split('.').slice(0,2).join('.')}.invalid`}}),401);
    await record('GET /api/data with valid token',await api.get(base+'/api/data',{headers}),200);
    const output={timestamp_utc:new Date().toISOString(),base_url:base,login:{status:200,token:'[redacted]'},checks,xss:{payload,dom_elements_created:0,script_executed:false,dialogs:dialogs.length,csp_bypass_context_also_passed:true}};
    fs.writeFileSync(path.join(raw,'browser-results.json'),JSON.stringify(output,null,2));
    await evidencePage(browser,'03-api-security-checks','Live API security checks','Actual HTTP responses from the local Flask application. JWT omitted.',JSON.stringify(output,null,2));
    await evidencePage(browser,'04-pytest','Automated functional and security tests','Actual pytest output; full log is preserved in evidence/raw/pytest.txt.',fs.readFileSync(path.join(raw,'pytest.txt'),'utf8'));
    const bandit=JSON.parse(fs.readFileSync(path.join(raw,'bandit.json'),'utf8'));
    const audit=JSON.parse(fs.readFileSync(path.join(raw,'pip-audit.json'),'utf8'));
    await evidencePage(browser,'05-security-scans','SAST and dependency audit','Actual scanner results. Scope: app/ source and requirements.txt runtime dependencies.',JSON.stringify({bandit:{generated_at:bandit.generated_at,metrics:bandit.metrics._totals,results:bandit.results,errors:bandit.errors},pip_audit:audit},null,2));
    console.log('Browser assertions passed. Five screenshots saved in evidence/screenshots.');
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exit(1);});
