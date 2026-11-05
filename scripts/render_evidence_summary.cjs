// Compact, Word-friendly views of real JSON evidence. No results are fabricated.
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(__dirname,'..');
const raw = path.join(root,'evidence/raw');
const shots = path.join(root,'evidence/screenshots');
const read = name => JSON.parse(fs.readFileSync(path.join(raw,name),'utf8'));
const escape = value => String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const table = (headers, rows) => `<table><thead><tr>${headers.map(v=>`<th>${escape(v)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(v=>`<td>${escape(v)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
(async()=>{
  const browser=await chromium.launch({channel:process.env.BROWSER_CHANNEL||'chrome',headless:true});
  async function capture(name,title,content){
    const html=`<!doctype html><meta charset="utf-8"><title>${escape(title)}</title><style>body{margin:0;padding:38px;background:#edf2f4;color:#182c38;font:16px/1.5 Arial}main{max-width:1080px;margin:auto}h1{margin:0 0 10px;font-size:30px}h2{font-size:20px;margin:26px 0 10px}p{color:#48616e}table{border-collapse:collapse;width:100%;background:white}th,td{border:1px solid #cbd8df;padding:10px 14px;text-align:left;overflow-wrap:anywhere}th{background:#dce8ee}code{font:14px Consolas}footer{margin-top:20px;font-size:13px;color:#48616e}</style><main><h1>${escape(title)}</h1>${content}<footer>IS Lab 1 · XiangBingYu · 23320211 · Screenshot of recorded evidence, not a terminal or GitHub UI.</footer></main>`;
    fs.writeFileSync(path.join(raw,name+'.html'),html);
    const page=await browser.newPage({viewport:{width:1280,height:850}});
    await page.setContent(html);
    await page.screenshot({path:path.join(shots,name+'.png'),fullPage:true});
    await page.close();
  }
  try{
    const live=read('browser-results.json');
    await capture('03-api-security-checks','Live API and browser checks',
      `<p>Source: browser-results.json · Recorded ${escape(live.timestamp_utc)} · JWT redacted.</p>`+
      table(['Request','HTTP status','Observed response'],live.checks.map(c=>[c.name,c.status,c.body.error||c.body.status||(c.body.notes.length+' note(s)')]))+
      '<h2>Stored XSS browser assertions</h2>'+table(['Assertion','Observed result'],[
        ['Injected script / image elements inside notes',live.xss.dom_elements_created],
        ['Payload executed',live.xss.script_executed],['Alert dialogs',live.xss.dialogs],
        ['Same assertions pass with CSP bypassed',live.xss.csp_bypass_context_also_passed]])
    );
    const bandit=read('bandit.json'),audit=read('pip-audit.json');
    await capture('05-security-scans','SAST and runtime dependency audit',
      `<p>Actual JSON results · Bandit generated ${escape(bandit.generated_at)}</p>`+
      table(['Bandit check','Result'],[['Unsuppressed findings',bandit.results.length],['Analysis errors',bandit.errors.length],['Locally suppressed checks',bandit.metrics._totals.skipped_tests],['Reviewed exception','B106: Bearer is a public authentication scheme, not a password']])+
      '<h2>pip-audit runtime package results</h2>'+table(['Package','Installed version','Known vulnerabilities'],audit.dependencies.map(d=>[d.name,d.version,d.vulns.length]))+
      '<p>Scope: app/ source and the pinned runtime dependency list. Original JSON and initial Bandit finding are preserved.</p>'
    );
    if(fs.existsSync(path.join(raw,'github-actions.json'))){
      const ci=read('github-actions.json');
      await capture('06-github-actions','GitHub Actions execution evidence',
        `<p>Retrieved from the GitHub API · ${escape(ci.retrieved_at)}</p><p>${escape(ci.html_url)}</p>`+
        table(['Field','Recorded value'],[['Repository','Xiangbingyu/IS-Lab1'],['Commit',ci.head_sha],['Status',ci.status],['Conclusion',ci.conclusion]])+
        '<h2>Remote jobs</h2>'+table(['Job','Status','Conclusion'],ci.jobs.map(j=>[j.name,j.status,j.conclusion]))+
        '<p>This screenshot shows verified API records. It is not a screenshot of the GitHub website.</p>'
      );
    }
    console.log('Compact evidence screenshots saved.');
  }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1);});
