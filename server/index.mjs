import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes,createHash } from 'node:crypto';
import { mkdirSync,readFileSync,existsSync } from 'node:fs';
import path from 'node:path';
import { audit,VERSION } from './audit.mjs';
import { normalize,resolvePublic } from './net.mjs';

const ROOT=path.resolve(import.meta.dirname,'..'),DIR=process.env.DATA_DIR||path.join(ROOT,'data');mkdirSync(DIR,{recursive:true});
const SITE=process.env.SITE_URL||'https://reach.mimxo.com',PORT=Number(process.env.PORT||8792),HOST=process.env.HOST||'127.0.0.1';
const db=new DatabaseSync(path.join(DIR,'reach.db'));
db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,origin TEXT,status TEXT,progress TEXT,result TEXT,error TEXT,created INTEGER); CREATE INDEX IF NOT EXISTS scans_origin ON scans(origin,created); CREATE TABLE IF NOT EXISTS leads(id INTEGER PRIMARY KEY,email TEXT,origin TEXT,note TEXT,consent INTEGER,created INTEGER); CREATE TABLE IF NOT EXISTS quotas(k TEXT PRIMARY KEY,n INTEGER,reset INTEGER);');
db.prepare("UPDATE scans SET status='error',error='Scan interrupted by a restart; please retry.' WHERE status IN ('queued','running')").run();
const get=(q,...p)=>db.prepare(q).get(...p),run=(q,...p)=>db.prepare(q).run(...p);
const now=()=>Math.floor(Date.now()/1000),queue=[];let active=0;
const esc=s=>String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function quota(key,max,seconds) {
  const r=get('SELECT * FROM quotas WHERE k=?',key);const t=now();
  if(!r||r.reset<=t){run('INSERT OR REPLACE INTO quotas VALUES(?,?,?)',key,1,t+seconds);return true;}
  if(r.n>=max)return false;run('UPDATE quotas SET n=n+1 WHERE k=?',key);return true;
}
function pump() {
  while(active<2&&queue.length) {
    const job=queue.shift();active++;
    run("UPDATE scans SET status='running' WHERE id=?",job.id);
    audit(job.origin,{progress:p=>run('UPDATE scans SET progress=? WHERE id=?',JSON.stringify(p),job.id)})
      .then(report=>run("UPDATE scans SET status='done',result=? WHERE id=?",JSON.stringify(report),job.id))
      .catch(e=>run("UPDATE scans SET status='error',error=? WHERE id=?",String(e.message).slice(0,200),job.id))
      .finally(()=>{active--;pump();});
  }
}
async function body(req) {
  let n=0;const chunks=[];
  for await(const c of req){n+=c.length;if(n>8000)throw Object.assign(new Error('Request too large.'),{status:413});chunks.push(c);}
  try {return JSON.parse(Buffer.concat(chunks).toString());}catch{throw Object.assign(new Error('Invalid JSON.'),{status:400});}
}
function output(res,status,value,type='application/json; charset=utf-8',headers={}) {
  res.writeHead(status,{'Content-Type':type,'X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin','Cache-Control':'no-store',...headers});
  res.end(type.startsWith('application/json')?JSON.stringify(value):value);
}
const titles={
  '/':['ReachCheck · Can agents actually reach your product?','A free, evidence-first audit of your public HTML, crawler policy and integration documents. No logins, purchases or certification claims.'],
  '/methodology':['How ReachCheck scores public agent access','An open, versioned checklist; unknown is not failure and optional files are not mandatory.'],
  '/docs':['ReachCheck API and agent guide','Create a bounded website audit and retrieve JSON evidence.'],
  '/privacy':['ReachCheck privacy policy','Data retention and privacy for public URL scans and optional audit requests.'],
  '/terms':['ReachCheck terms','A static research tool, not a security, compliance, indexing or transaction guarantee.'],
  '/benchmarks':['ReachCheck · 50 public-site document audits','A dated, bounded sample of public access signals—not a ranking of company quality.']
};
const schema={openapi:'3.1.0',info:{title:'ReachCheck API',version:'1.0.0',description:'Public-document readiness, not end-to-end agent execution. Unauthenticated, rate limited; private targets blocked.'},servers:[{url:SITE}],paths:{
 '/api/scans':{post:{summary:'Create or reuse a bounded public-URL scan',requestBody:{required:true,content:{'application/json':{schema:{type:'object',required:['url'],properties:{url:{type:'string',format:'uri'}}}}}},responses:{202:{description:'Queued; poll Location'},200:{description:'Cached result'},400:{description:'Unsafe/invalid target'},429:{description:'Rate limited'}}}},
 '/api/scans/{id}':{get:{summary:'Read status and evidence',parameters:[{name:'id',in:'path',required:true,schema:{type:'string'}}],responses:{200:{description:'Status and optional report'},404:{description:'Unknown or expired report'}}}},
 '/api/scans/{id}/export':{get:{summary:'Download full JSON report',parameters:[{name:'id',in:'path',required:true,schema:{type:'string'}}],responses:{200:{description:'JSON report'},404:{description:'Report unavailable'}}}}
}};

const server=http.createServer(async(req,res)=>{
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  try {
    const u=new URL(req.url,'http://localhost'),p=u.pathname;
    // Trust forwarded client identity only behind the loopback-bound nginx origin.
    const ip=req.headers['x-real-ip']||req.socket.remoteAddress;
    const client=createHash('sha256').update(String(ip)+process.env.RATE_SALT).digest('hex').slice(0,24);
    if(p.startsWith('/api/'))res.setHeader('X-Robots-Tag','noindex');
    if(req.method==='GET'&&p==='/healthz')return output(res,200,{ok:true,active,queued:queue.length,version:VERSION});
    if(req.method==='GET'&&p==='/openapi.json')return output(res,200,schema);
    if(req.method==='GET'&&p==='/.well-known/agent-card.json')return output(res,200,{name:'ReachCheck',url:SITE,description:'Bounded read-only public website audits',interfaces:[{type:'http',url:SITE+'/openapi.json'}],documentation:SITE+'/docs',authentication:'none; rate limited',limitations:['No login, payment or API execution','Not an A2A endpoint']});
    if(req.method==='GET'&&p==='/api/stats')return output(res,200,{completed:get("SELECT count(*) n FROM scans WHERE status='done'").n,active,version:VERSION});
    if(req.method==='POST'&&p==='/api/scans') {
      if(req.headers.origin&&req.headers.origin!==SITE)return output(res,403,{error:'Cross-origin submissions are not allowed.'});
      const b=await body(req);const target=normalize(b.url);await resolvePublic(target.hostname.replace(/^\[|\]$/g,''));
      const cached=get("SELECT id,status FROM scans WHERE origin=? AND created>? AND (status IN ('queued','running') OR (status='done' AND json_extract(result,'$.version')=?)) ORDER BY created DESC LIMIT 1",target.origin,now()-21600,VERSION);
      if(cached)return output(res,cached.status==='done'?200:202,{id:cached.id,status:cached.status,cached:true,reportUrl:SITE+'/r/'+cached.id});
      if(!quota('scan:'+client,5,3600)||!quota('global',100,3600)||queue.length>=20)return output(res,429,{error:'Audit capacity reached. Try later or contact support.',retryAfter:3600},undefined,{'Retry-After':'3600'});
      const id=randomBytes(16).toString('hex');run('INSERT INTO scans VALUES(?,?,?,?,?,?,?)',id,target.origin,'queued','{}',null,null,now());queue.push({id,origin:target.origin});pump();
      return output(res,202,{id,status:'queued',reportUrl:SITE+'/r/'+id},undefined,{Location:'/api/scans/'+id});
    }
    const reportRoute=p.match(/^\/api\/scans\/([a-f0-9]{32})(?:\/(export|llms|card))?$/);
    if(req.method==='GET'&&reportRoute) {
      const [,id,kind]=reportRoute,r=get('SELECT * FROM scans WHERE id=?',id);if(!r)return output(res,404,{error:'Unknown or expired report.'});
      const report=r.result?JSON.parse(r.result):null;
      if(kind&&!report)return output(res,409,{error:'Report is not ready.'});
      if(kind==='export')return output(res,200,report,undefined,{'Content-Disposition':`attachment; filename="reachcheck-${id}.json"`});
      if(kind==='llms')return output(res,200,report.artifacts.llms,'text/markdown; charset=utf-8',{'Content-Disposition':'attachment; filename="llms-draft.txt"'});
      if(kind==='card')return output(res,200,report.artifacts.card,undefined,{'Content-Disposition':'attachment; filename="agent-card-draft.json"'});
      return output(res,200,{id:r.id,status:r.status,progress:JSON.parse(r.progress||'{}'),error:r.error,report});
    }
    if(req.method==='POST'&&p==='/api/leads') {
      if(req.headers.origin&&req.headers.origin!==SITE)return output(res,403,{error:'Wrong origin.'});
      if(!quota('lead:'+client,3,86400))return output(res,429,{error:'Request limit reached.'});
      const b=await body(req);
      if(b.website)return output(res,200,{ok:true});
      if(b.consent!==true||typeof b.email!=='string'||!/^[^\s@]{1,100}@[^\s@.]+\.[^\s@]{2,40}$/.test(b.email)||b.email.length>254)return output(res,400,{error:'A valid email and explicit consent are required.'});
      let origin='';if(b.url)origin=normalize(b.url).origin;
      run('INSERT INTO leads(email,origin,note,consent,created) VALUES(?,?,?,?,?)',b.email,origin,String(b.note||'').slice(0,2000),1,now());
      return output(res,201,{ok:true,message:'Request saved. No payment was taken; contact support@mimxo.com for a prompt response.'});
    }
    if(req.method==='GET'&&p==='/api/benchmarks') {
      const file=path.join(ROOT,'public','benchmark.json');return output(res,200,existsSync(file)?JSON.parse(readFileSync(file,'utf8')):{status:'not_published',items:[]});
    }
    if(req.method!=='GET'&&req.method!=='HEAD')return output(res,405,{error:'Method not supported.'},undefined,{Allow:'GET, HEAD'});
    if(p==='/robots.txt')return output(res,200,`User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /r/\nSitemap: ${SITE}/sitemap.xml\n`,'text/plain; charset=utf-8');
    if(p==='/sitemap.xml')return output(res,200,`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${Object.keys(titles).map(x=>`<url><loc>${SITE}${x}</loc></url>`).join('')}</urlset>`,'application/xml; charset=utf-8');
    if(p==='/llms.txt')return output(res,200,`# ReachCheck\n\n> Evidence-first, read-only public website audit. No agent certification or search ranking guarantee.\n\n- [API guide](${SITE}/docs)\n- [Methodology](${SITE}/methodology)\n- [OpenAPI](${SITE}/openapi.json)\n- [Privacy](${SITE}/privacy)\n\nPOST /api/scans with {"url":"https://example.org"}. Poll /api/scans/{id}. Limits: five new scans per IP per hour; two concurrent audits globally. Results cached six hours; deleted after thirty days. Contact support@mimxo.com. No API key needed.\n`,'text/markdown; charset=utf-8');
    const files={'/app.js':['app.js','text/javascript'],'/styles.css':['styles.css','text/css'],'/favicon.svg':['favicon.svg','image/svg+xml'],'/og.png':['og.png','image/png']};
    if(files[p]){const [file,type]=files[p];return output(res,200,req.method==='HEAD'?'':readFileSync(path.join(ROOT,'public',file)),type+(type==='image/png'?'':'; charset=utf-8'),{'Cache-Control':'public,max-age=300'});}
    if(titles[p]||/^\/r\/[a-f0-9]{32}$/.test(p)) {
      const [title,desc]=titles[p]||['ReachCheck · Your audit report','An unlisted public-URL audit.'];
      let html=readFileSync(path.join(ROOT,'public/index.html'),'utf8').replaceAll('__TITLE__',esc(title)).replaceAll('__DESCRIPTION__',esc(desc)).replaceAll('__CANONICAL__',esc(SITE+p));
      if(titles[p] && p!=='/') {
        const extra=p==='/docs'?'<pre>POST /api/scans {"url":"https://example.org"}\nGET /api/scans/{id}\nGET /api/scans/{id}/export</pre><p>No API key required. Five new scans per IP per hour. Reports cached six hours; deleted after thirty days. No credentials or cookies accepted. 202 means queued, 400 refuses unsafe targets, 429 requires waiting for the current rate window.</p>':p==='/methodology'?'<p>Eleven explicit checks: HTTPS 8, response 12, readable HTML 18, robots policy 12, metadata 8, structured data 8, llms.txt 8, docs 8, OpenAPI 8, agent card 4, support handoff 6. Score is passed weight divided by measured weight. Unknown checks are excluded; below 50% coverage no score is issued. Optional discovery files are not mandatory. No login, purchase, JavaScript rendering or live API execution is tested.</p>':p==='/privacy'?'<p>Scan origins, reports, source links, short excerpts and timing are retained thirty days. Full pages are not retained. Unlisted report links are readable by anyone who has the link. Voluntary email requests are retained ninety days. Rate limits use hashed network identifiers; proxy logs may retain IPs and URLs. Cloudflare and our server process data. Backups rotate after fourteen days; contact support for deletion.</p>':p==='/terms'?'<p>Inspect only lawful public targets. Do not submit credentials or private addresses. A score is a bounded technical heuristic, not certification, security advice, compliance approval, financial advice or a conversion guarantee. Assisted work needs separate agreement on owner authorization, scope, pricing and acceptance. There is no paid checkout or monitoring subscription. Mandatory consumer rights are not excluded.</p>':'<p>One dated, read-only public-document sample. Results are alphabetical, not a ranking of product quality or agent success. Access restrictions and network failures remain unknown. See the interactive sample and each evidence report below.</p>';
        const main=`<main id="app"><article class="wrap doc"><h1>${esc(title)}</h1><p>${esc(desc)}</p>${extra}<p><a href="/methodology">Methodology</a> · <a href="/openapi.json">OpenAPI</a> · <a href="mailto:support@mimxo.com">Support</a></p></article></main>`;
        html=html.replace(/<main id="app">[\s\S]*?<\/main>/,main);
      }
      if(p.startsWith('/r/'))res.setHeader('X-Robots-Tag','noindex');
      return output(res,200,req.method==='HEAD'?'':html,'text/html; charset=utf-8');
    }
    return output(res,404,'Not found.','text/plain; charset=utf-8');
  }catch(e){return output(res,e.status||(['invalid_url','unsafe_target','dns_timeout'].includes(e.code)?400:500),{error:e.code|| (e.status?e.message:'Request could not be completed.')});}
});
server.headersTimeout=15000;server.requestTimeout=30000;
server.listen(PORT,HOST,()=>console.log(`ReachCheck on ${HOST}:${PORT}`));
const retention=setInterval(()=>{
  run('DELETE FROM scans WHERE created<?',now()-30*86400);run('DELETE FROM quotas WHERE reset<?',now());run('DELETE FROM leads WHERE created<?',now()-90*86400);
},3600000);retention.unref();
