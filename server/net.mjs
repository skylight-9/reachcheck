import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';

export class FetchError extends Error { constructor(code, message) { super(message); this.code = code; } }
export function publicIP(address) {
  if (isIP(address) === 4) {
    const [a,b,c] = address.split('.').map(Number);
    if ([0,10,127].includes(a) || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
        (a === 192 && b === 0 && c === 2) || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
        (a === 203 && b === 0 && c === 113)) return false;
    return true;
  }
  if (isIP(address) === 6) {
    // Only global unicast 2000::/3; exclude special/documentation/transition space.
    const s = address.toLowerCase();
    return /^[23][0-9a-f]{0,3}:/.test(s) && !s.startsWith('2001:') && !s.startsWith('2002:') && !s.startsWith('3fff:');
  }
  return false;
}
export function normalize(input) {
  const raw = String(input || '').trim();
  if (!raw || raw.length > 2048) throw new FetchError('invalid_url', 'Enter a public website URL.');
  let u;
  try { u = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : 'https://' + raw); }
  catch { throw new FetchError('invalid_url', 'Invalid URL.'); }
  if (!['http:','https:'].includes(u.protocol) || u.username || u.password || u.port) throw new FetchError('invalid_url', 'Only HTTP/HTTPS on standard ports, without credentials.');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host === 'localhost' || /\.(localhost|local|internal|test|invalid|example)$/i.test(host) || (!host.includes('.') && !isIP(host))) throw new FetchError('unsafe_target', 'Only public internet sites are supported.');
  if (isIP(host) && !publicIP(host)) throw new FetchError('unsafe_target', 'Private and reserved addresses are not allowed.');
  u.hash = ''; u.search = '';
  return u;
}
export async function resolvePublic(host, resolver = dns.lookup) {
  let timer;
  const addresses = await Promise.race([
    resolver(host, {all:true, verbatim:true}),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new FetchError('dns_timeout','DNS lookup timed out.')), 7000); })
  ]).finally(() => clearTimeout(timer));
  const blocked = (process.env.BLOCKED_IPS || '5.253.17.14').split(',');
  if (!addresses.length || addresses.some(x => !publicIP(x.address) || blocked.includes(x.address))) throw new FetchError('unsafe_target', 'DNS returned a private, reserved, or blocked address.');
  return addresses.find(x => x.family === 4) || addresses[0];
}

export async function safeFetch(input, { maxBytes=400000, timeout=9000, redirects=4 }={}) {
  const start = Date.now();
  const request = async (url, remaining) => {
    const u = normalize(url), host = u.hostname.replace(/^\[|\]$/g,'');
    const pin = await resolvePublic(host);
    return new Promise((resolve, reject) => {
      const transport = u.protocol === 'https:' ? https : http;
      let ended = false;
      const done = (err, val) => { if (ended) return; ended=true; clearTimeout(timer); err ? reject(err) : resolve(val); };
      const req = transport.request(u, {
        method:'GET', agent:false, servername:host,
        lookup: (_host, options, cb) => options.all ? cb(null,[pin]) : cb(null,pin.address,pin.family),
        headers:{'User-Agent':'ReachCheck/1.0 (+https://reach.mimxo.com/methodology; read-only public-site audit)', 'Accept':'text/html,text/plain,application/json,application/xml;q=0.9,*/*;q=0.1','Accept-Encoding':'identity'}
      }, res => {
        const code = res.statusCode;
        if ([301,302,303,307,308].includes(code) && res.headers.location) {
          res.destroy(); clearTimeout(timer); ended=true;
          if (!remaining) return reject(new FetchError('redirect_limit','Too many redirects.'));
          let next;
          try { next = normalize(new URL(res.headers.location,u).href); } catch(e) { return reject(e); }
          request(next.href,remaining-1).then(resolve,reject); return;
        }
        const chunks=[]; let size=0;
        res.on('data', data => {
          size += data.length;
          if(size > maxBytes) {
            const remaining=maxBytes-(size-data.length);if(remaining>0)chunks.push(data.subarray(0,remaining));
            done(null,{url:u.href,status:code,headers:res.headers,body:Buffer.concat(chunks).toString('utf8'),ms:Date.now()-start,bytes:maxBytes,truncated:true});
            res.destroy();req.destroy();
          } else chunks.push(data);
        });
        res.on('end', () => done(null,{url:u.href,status:code,headers:res.headers,body:Buffer.concat(chunks).toString('utf8'),ms:Date.now()-start,bytes:size}));
        res.on('error', e => done(new FetchError('network_error',e.message)));
      });
      const timer=setTimeout(() => { done(new FetchError('timeout','Response timed out.')); req.destroy(); },timeout);
      req.on('error', e => done(new FetchError('network_error', e.message)));
      req.end();
    });
  };
  return request(input, redirects);
}

export function parseRobots(body) {
  const groups=[]; let agents=[], rules=[];
  const flush = () => { if(agents.length) groups.push({agents:[...agents],rules:[...rules]}); agents=[];rules=[]; };
  for(const line of body.split(/\r?\n/)) {
    const m=line.replace(/#.*/,'').match(/^\s*(user-agent|allow|disallow)\s*:\s*(.*)$/i);
    if(!m) continue;
    if(m[1].toLowerCase()==='user-agent') { if(rules.length) flush();agents.push(m[2].trim().toLowerCase()); }
    else if(agents.length) rules.push({allow:m[1].toLowerCase()==='allow',path:m[2].trim()});
  }
  flush();return groups;
}
export function robotsAllowed(body, agent, path) {
  const groups=parseRobots(body); const name=agent.toLowerCase();
  let applicable=groups.filter(g=>g.agents.some(a=>a!=='*' && name.includes(a)));
  if(!applicable.length) applicable=groups.filter(g=>g.agents.includes('*'));
  const rules=applicable.flatMap(g=>g.rules).filter(r=>r.path);
  const matches=rules.filter(r=>{
    const escaped=r.path.replace(/[.+?^{}()|[\]\\]/g,'\\$&').replace(/\*/g,'.*');
    return new RegExp('^'+escaped).test(path);
  }).sort((a,b)=>b.path.replace(/[*$]/g,'').length-a.path.replace(/[*$]/g,'').length || Number(b.allow)-Number(a.allow));
  return matches.length ? matches[0].allow : true;
}
