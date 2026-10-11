// Operator-only, one-off sample. Uses the same audit function, two workers, robots respected.
// This is not a public API rate-limit bypass offered to users.
import {audit,VERSION} from '../server/audit.mjs';
import {DatabaseSync} from 'node:sqlite';import {randomBytes} from 'node:crypto';
import {writeFileSync} from 'node:fs';import path from 'node:path';
const sites=['mimxo.com','agora.mimxo.com','github.com','gitlab.com','vercel.com','netlify.com','cloudflare.com','supabase.com','firebase.google.com','railway.com','render.com','fly.io','notion.so','linear.app','slack.com','discord.com','figma.com','canva.com','miro.com','tally.so','typeform.com','jotform.com','cal.com','calendly.com','zapier.com','make.com','n8n.io','airtable.com','asana.com','trello.com','clickup.com','monday.com','postman.com','insomnia.rest','sentry.io','datadoghq.com','grafana.com','plausible.io','umami.is','posthog.com','stripe.com','paddle.com','creem.io','lemonsqueezy.com','resend.com','mailchimp.com','brevo.com','intercom.com','crisp.chat','helpscout.com'];
const dir=process.env.DATA_DIR||'/app/data',db=new DatabaseSync(path.join(dir,'reach.db'));db.exec('PRAGMA busy_timeout=5000');
let cursor=0;const items=[];
async function worker(){while(cursor<sites.length){const host=sites[cursor++],id=randomBytes(16).toString('hex');let report;
 try{report=await audit('https://'+host);}catch(e){console.error('Audit error',host,e.code||e.message);report={version:VERSION,createdAt:new Date().toISOString(),site:{origin:'https://'+host,title:host},score:null,coverage:0,findings:[],observations:[],limitations:['Audit failed; no conclusion issued.'],artifacts:{llms:'# Draft\n',card:{status:'draft'}}};}
 db.prepare('INSERT INTO scans VALUES(?,?,?,?,?,?,?)').run(id,'https://'+host,'done','{}',JSON.stringify(report),null,Math.floor(Date.now()/1000));
 items.push({host,id,score:report.score,coverage:report.coverage,unknown:report.findings.filter(x=>['unknown','not_checked'].includes(x.status)).length,observedAt:report.createdAt});
 console.log(`Sample ${items.length}/50: ${host} coverage=${report.coverage} score=${report.score??'unknown'}`);
}}
await Promise.all([worker(),worker()]);
items.sort((a,b)=>a.host.localeCompare(b.host));
const out={date:new Date().toISOString(),version:VERSION,method:'Identifiable read-only GETs, static HTML, one network location, common document paths, no login/payment/tool invocation.',notARanking:true,items};
writeFileSync(path.resolve(import.meta.dirname,'../public/benchmark.json'),JSON.stringify(out,null,2));
writeFileSync(path.join(dir,'benchmark-receipt.json'),JSON.stringify(out,null,2));db.close();
console.log('Complete: 50 sampled sites. Known scoring results',items.filter(x=>x.score!==null).length);
