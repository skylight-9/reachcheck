import test from 'node:test';import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';import {mkdtempSync,rmSync} from 'node:fs';import os from 'node:os';import path from 'node:path';
test('HTTP integration: health, SSR docs, unsafe URLs, lead validation, privacy and unknown report',async t=>{
 const dir=mkdtempSync(path.join(os.tmpdir(),'reachcheck-test-'));
 const port=19800+Math.floor(Math.random()*1000),base=`http://127.0.0.1:${port}`;
 const child=spawn(process.execPath,['--disable-warning=ExperimentalWarning','server/index.mjs'],{env:{...process.env,DATA_DIR:dir,PORT:String(port),SITE_URL:base,RATE_SALT:'test'}});
 t.after(()=>{child.kill();rmSync(dir,{recursive:true,force:true});});
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('server startup timeout')),5000);child.stdout.once('data',()=>{clearTimeout(timer);resolve();});child.once('exit',code=>reject(Error('server exited '+code)));});
 const request=(p,b,origin=base)=>fetch(base+p,{method:b?'POST':'GET',headers:b?{'Content-Type':'application/json',Origin:origin}:{},body:b?JSON.stringify(b):undefined});
 assert.equal((await request('/healthz')).status,200);
 const docs=await(await request('/docs')).text();assert.ok(docs.includes('POST /api/scans'));assert.ok(docs.includes('No API key required'));
 for(const url of ['http://127.0.0.1','http://169.254.169.254','https://admin:secret@example.org','http://[::1]'])assert.equal((await request('/api/scans',{url})).status,400);
 assert.equal((await request('/api/scans',{url:'https://example.org'},'https://evil.example.org')).status,403);
 assert.equal((await request('/api/scans/'+'a'.repeat(32))).status,404);
 assert.equal((await request('/api/leads',{email:'bad',consent:true})).status,400);
 assert.equal((await request('/api/leads',{email:'person@example.org',note:'Review my docs',consent:true})).status,201);
 const r=await request('/r/'+'a'.repeat(32));assert.equal(r.headers.get('x-robots-tag'),'noindex');
 assert.ok((await(await request('/robots.txt')).text()).includes('Disallow: /r/'));
});
