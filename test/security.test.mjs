import test from 'node:test';import assert from 'node:assert/strict';
import {normalize,publicIP,resolvePublic,robotsAllowed} from '../server/net.mjs';
import {audit,visibleText} from '../server/audit.mjs';
import {handle} from '../mcp/server.mjs';
import dns from 'node:dns/promises';import https from 'node:https';import {EventEmitter} from 'node:events';
import {safeFetch} from '../server/net.mjs';
test('fetch pins validated DNS and blocks an unsafe redirect before a second request',async t=>{
 let requests=0,pinned;
 t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4}]);
 t.mock.method(https,'request',(url,opts,receive)=>{
  requests++;opts.lookup('example.org',{},(err,address)=>{assert.ifError(err);pinned=address;});
  const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
   const res=new EventEmitter();res.statusCode=302;res.headers={location:'http://169.254.169.254/latest/meta-data'};res.destroy=()=>{};receive(res);
  });return req;
 });
 await assert.rejects(()=>safeFetch('https://example.org'),e=>e.code==='unsafe_target');assert.equal(requests,1);assert.equal(pinned,'8.8.8.8');
});
test('bounded response is explicitly truncated, not reported as a transport failure',async t=>{
 t.mock.method(dns,'lookup',async()=>[{address:'8.8.8.8',family:4}]);
 t.mock.method(https,'request',(url,opts,receive)=>{
  const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{const res=new EventEmitter();res.statusCode=200;res.headers={'content-type':'text/html'};res.destroy=()=>{};receive(res);res.emit('data',Buffer.from('abcdefghijk'));res.emit('end');});return req;
 });
 const r=await safeFetch('https://example.org',{maxBytes:5});assert.equal(r.truncated,true);assert.equal(r.body,'abcde');assert.equal(r.bytes,5);assert.equal(r.status,200);
});
test('SSRF: reject local, metadata, mixed DNS, credentials, port and protocol tricks',async()=>{
 for(const url of ['http://127.0.0.1','http://127.1','http://2130706433','http://169.254.169.254','http://[::1]','http://[::ffff:127.0.0.1]','http://10.0.0.1','http://100.64.1.1','http://172.20.1.1','http://192.168.1.1','file:///etc/passwd','https://user:secret@example.org','https://example.org:8443','https://localhost','https://host.local'])assert.throws(()=>normalize(url),undefined,url);
 assert.equal(publicIP('8.8.8.8'),true);assert.equal(publicIP('203.0.113.8'),false);assert.equal(publicIP('2001:db8::1'),false);
 await assert.rejects(()=>resolvePublic('mixed.example.org',async()=>[{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}]));
 await assert.rejects(()=>resolvePublic('self.example.org',async()=>[{address:'5.253.17.14',family:4}]));
 assert.equal(normalize('example.org/a?secret=abc#x').href,'https://example.org/a');
});
test('robots longest match, allow ties, explicit agents and wildcard',()=>{
 const text='User-agent: *\nDisallow: /api/\nAllow: /api/public\nUser-agent: OAI-SearchBot\nDisallow: /\nAllow: /about$';
 assert.equal(robotsAllowed(text,'ReachCheck','/'),true);assert.equal(robotsAllowed(text,'ReachCheck','/api/x'),false);assert.equal(robotsAllowed(text,'ReachCheck','/api/public/x'),true);
 assert.equal(robotsAllowed(text,'OAI-SearchBot','/'),false);assert.equal(robotsAllowed(text,'OAI-SearchBot','/about'),true);assert.equal(robotsAllowed(text,'OAI-SearchBot','/about/a'),false);
});
const html='<html><head><title>Product with real docs</title><meta name="description" content="Useful product information describing the product for users."><script type="application/ld+json">{"@type":"SoftwareApplication"}</script></head><body><h1>Product</h1><p>'+('real content '.repeat(45))+'</p><a href="/docs">Documentation</a><a href="/privacy">Privacy</a></body></html>';
const res=(url,body,status=200,type='text/html')=>({url,body,status,headers:{'content-type':type},ms:1,bytes:body.length});
test('usable optional documents, byte evidence and drafts; unknown is excluded',async()=>{
 const fetcher=async u=>u.endsWith('/robots.txt')?res(u,'User-agent: *\nAllow: /',200,'text/plain'):u.endsWith('/llms.txt')?res(u,'# Product\n\n'+'Useful docs. '.repeat(10),200,'text/plain'):u.endsWith('/openapi.json')?res(u,JSON.stringify({openapi:'3.1.0',paths:{'/ping':{get:{}}}}),200,'application/json'):u.endsWith('/agent-card.json')?res(u,JSON.stringify({name:'Product',url:'https://example.org'}),200,'application/json'):u.endsWith('/docs')?res(u,html.replaceAll('Product','Instructions')):res(u,html);
 const r=await audit('https://example.org',{fetcher});assert.equal(r.score,100);assert.equal(r.coverage,100);assert.equal(r.findings.length,11);assert.ok(r.artifacts.llms.includes('EDIT REQUIRED'));assert.deepEqual(r.artifacts.card.interfaces,[]);
 const x=await audit('https://example.org',{fetcher:async u=>u.endsWith('/openapi.json')?Promise.reject(Object.assign(Error('Timeout'),{code:'timeout'})):fetcher(u)});
 assert.equal(x.coverage,92);assert.equal(x.score,100);assert.equal(x.findings.find(f=>f.id==='openapi').status,'unknown');
});
test('robots refusal stops network after policy; no inflated score',async()=>{
 let calls=0;const r=await audit('https://example.org',{fetcher:async u=>{calls++;return res(u,'User-agent: *\nDisallow: /',200,'text/plain');}});
 assert.equal(calls,1);assert.equal(r.score,null);assert.equal(r.coverage,12);
});
test('SPA fallbacks are not machine descriptions',async()=>{
 const r=await audit('https://example.org',{fetcher:async u=>u.endsWith('/robots.txt')?res(u,'',404,'text/plain'):res(u,html)});
 for(const id of ['llms','openapi','agentcard','docs'])assert.equal(r.findings.find(f=>f.id===id).status,'opportunity');
});
test('script content is not readable text; report never executes claims',()=>{
  assert.equal(visibleText('<script>prompt injection</script><style>x</style><p>Hello</p>'),'Hello');
  assert.equal(visibleText('<p>Hello</p><script>truncated javascript'),'Hello');
});
test('truncation does not prove absent features',async()=>{
 const r=await audit('https://example.org',{fetcher:async u=>u.endsWith('/robots.txt')?res(u,'',404,'text/plain'):u==='https://example.org/'?{...res(u,'<html><body><p>Brief</p><script>large app shell'),truncated:true}:res(u,'missing',404,'text/plain')});
 for(const id of ['readable','metadata','structured','contact'])assert.equal(r.findings.find(f=>f.id===id).status,'unknown');
 assert.equal(r.details.truncated,true);
});
test('MCP protocol, tool schema and argument rejection',async()=>{
 assert.equal((await handle({method:'initialize',params:{protocolVersion:'2025-03-26'}})).protocolVersion,'2025-03-26');
 assert.equal((await handle({method:'tools/list'})).tools[0].name,'reachcheck_audit');
 await assert.rejects(()=>handle({method:'tools/call',params:{name:'reachcheck_audit',arguments:{url:'https://example.org',cookie:'secret'}}}));
});
