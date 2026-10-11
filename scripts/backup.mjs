import {DatabaseSync} from 'node:sqlite';import {mkdirSync,readdirSync,unlinkSync} from 'node:fs';import path from 'node:path';
const dir=process.env.DATA_DIR||'/app/data',backup=path.join(dir,'backups');mkdirSync(backup,{recursive:true});
const today=new Date().toISOString().slice(0,10),file=path.join(backup,`reach-${today}.db`);
const db=new DatabaseSync(path.join(dir,'reach.db'));if(!readdirSync(backup).includes(path.basename(file)))db.exec(`VACUUM INTO '${file.replaceAll("'","''")}'`);db.close();
for(const name of readdirSync(backup).filter(x=>/^reach-\d{4}-\d{2}-\d{2}\.db$/.test(x)).sort().slice(0,-14))unlinkSync(path.join(backup,name));
console.log('Backup complete:',today);
