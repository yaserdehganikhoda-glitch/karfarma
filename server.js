// سرور کارفرما — بدون وابستگی. اجرا: node server.js  (نیازمند Node 22.13+)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { Worker, MessageChannel, receiveMessageOnPort } = require('worker_threads');
const PORT = process.env.PORT || 3000, DIR = __dirname;
let db;
if (process.env.TURSO_URL) {   // حالت ابری رایگان: دیتابیس Turso (بدون نیاز به دیسک دائمی)
  const base = process.env.TURSO_URL.replace(/^libsql:/, 'https:').replace(/\/$/, ''), tok = process.env.TURSO_TOKEN || '';
  const wk = new Worker(`const {parentPort}=require('worker_threads');parentPort.on('message',async({sab,port,base,tok,body})=>{let o;try{const r=await fetch(base+'/v2/pipeline',{method:'POST',headers:{Authorization:'Bearer '+tok,'Content-Type':'application/json'},body});o={s:r.status,t:await r.text()}}catch(e){o={s:0,t:String(e)}}port.postMessage(o);const a=new Int32Array(sab);Atomics.store(a,0,1);Atomics.notify(a,0)})`, { eval: true });
  const call = reqs => {   // فراخوانی هم‌زمان (sync) از طریق thread کمکی
    const sab = new SharedArrayBuffer(4), { port1, port2 } = new MessageChannel();
    wk.postMessage({ sab, port: port2, base, tok, body: JSON.stringify({ requests: reqs.concat({ type: 'close' }) }) }, [port2]);
    Atomics.wait(new Int32Array(sab), 0, 0);
    const { s, t } = receiveMessageOnPort(port1).message;
    if (s !== 200) throw new Error('DB ' + s + ' ' + String(t).slice(0, 200));
    return JSON.parse(t).results.slice(0, reqs.length).map(r => { if (r.type === 'error') throw new Error(r.error.message); return r.response.result; });
  };
  const arg = v => v == null ? { type: 'null' } : typeof v === 'number' ? (Number.isInteger(v) ? { type: 'integer', value: String(v) } : { type: 'float', value: v }) : { type: 'text', value: String(v) };
  const cell = c => c.type === 'null' ? null : c.type === 'integer' ? Number(c.value) : c.value;
  const rows = r => r.rows.map(row => Object.fromEntries(r.cols.map((c, i) => [c.name, cell(row[i])])));
  const st = (sql, a) => ({ type: 'execute', stmt: { sql, args: (a || []).map(arg) } });
  db = {
    prepare: sql => ({ all: (...a) => rows(call([st(sql, a)])[0]), get: (...a) => rows(call([st(sql, a)])[0])[0], run: (...a) => (call([st(sql, a)]), {}) }),
    exec: sql => { const l = sql.split(';').filter(x => x.trim()); if (l.length) call(l.map(x => st(x))); },
    batch: list => { for (let k = 0; k < list.length; k += 300) call([st('BEGIN')].concat(list.slice(k, k + 300).map(([q, a]) => st(q, a)), st('COMMIT'))); }
  };
} else {   // حالت محلی: فایل SQLite
  const { DatabaseSync } = require('node:sqlite'), d = new DatabaseSync(process.env.DB_FILE || path.join(DIR, 'karfarma.db'));
  db = { prepare: q => d.prepare(q), exec: q => d.exec(q),
    batch: l => { d.exec('BEGIN'); try { l.forEach(([q, a]) => d.prepare(q).run(...a)); d.exec('COMMIT'); } catch (e) { d.exec('ROLLBACK'); throw e; } } };
}
db.exec(`CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, name TEXT, role TEXT, salt TEXT, hash TEXT, last_sync INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS records(worker TEXT, id TEXT, updated INTEGER, data TEXT, month TEXT, qty REAL, total REAL, PRIMARY KEY(worker,id));
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT, worker TEXT, amount REAL, date TEXT, note TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT, worker TEXT, title TEXT, qty REAL, due TEXT, status TEXT DEFAULT 'new', note TEXT, created INTEGER);`);
const hash = (p, s) => crypto.scryptSync(p, s, 32).toString('hex');
const setUser = (u, n, role, p) => { const s = crypto.randomBytes(8).toString('hex');
  db.prepare('INSERT OR REPLACE INTO users(username,name,role,salt,hash,last_sync) VALUES(?,?,?,?,?,COALESCE((SELECT last_sync FROM users WHERE username=?),0))').run(u, n, role, s, hash(p, s), u); };
let sec = db.prepare("SELECT v FROM meta WHERE k='secret'").get();
if (!sec) { sec = { v: crypto.randomBytes(24).toString('hex') }; db.prepare("INSERT INTO meta VALUES('secret',?)").run(sec.v); }
if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  const p = process.env.ADMIN_PASS || crypto.randomBytes(4).toString('hex');
  setUser('admin', 'کارفرما', 'admin', p); console.log(`\n>>> کارفرما: نام کاربری admin | رمز ${p}\n`); }
if (process.env.RESET_ADMIN_PASS) { setUser('admin', 'کارفرما', 'admin', process.env.RESET_ADMIN_PASS); console.log('\n>>> رمز admin بازنشانی شد. حالا متغیر RESET_ADMIN_PASS را بردارید.\n'); }
const sign = u => { const b = Buffer.from(JSON.stringify({ u, e: Date.now() + 30 * 864e5 })).toString('base64url');
  return b + '.' + crypto.createHmac('sha256', sec.v).update(b).digest('base64url'); };
const verify = t => { try { const [b, s] = String(t).split('.');
  if (s !== crypto.createHmac('sha256', sec.v).update(b).digest('base64url')) return null;
  const o = JSON.parse(Buffer.from(b, 'base64url')); return o.e > Date.now() ? db.prepare('SELECT username,name,role FROM users WHERE username=?').get(o.u) : null; } catch { return null; } };
const send = (res, c, o, t = 'application/json') => { res.writeHead(c, { 'Content-Type': t + '; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Max-Age': '86400' }); res.end(typeof o === 'string' ? o : JSON.stringify(o)); };
const body = req => new Promise(r => { let d = ''; req.on('data', c => { d += c; if (d.length > 2e7) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); });
const fails = {}, regs = {};
const ipOf = req => String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress;
const num = v => Number.isFinite(+v) ? +v : 0;

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'), p = url.pathname;
  if (req.method === 'OPTIONS') return send(res, 204, '');
  if (!p.startsWith('/api/')) {
    const f = p === '/app' ? 'index.html' : p === '/' ? 'karfarma.html' : path.basename(p);
    const fp = path.join(DIR, f);
    return fs.existsSync(fp) && /^(index|karfarma)\.html$|\.png$|^manifest\.json$/.test(f) ? send(res, 200, fs.readFileSync(fp, 'utf8'), f.endsWith('.html') ? 'text/html' : 'application/octet-stream') : send(res, 404, 'not found', 'text/plain');
  }
  const b = req.method === 'GET' ? {} : await body(req);
  if (p === '/api/register' && req.method === 'POST') {   // ثبت‌نام کارگر از داخل برنامه (تا تأیید کارفرما: role=pending)
    const ip = ipOf(req), R = (regs[ip] = (regs[ip] || []).filter(t => Date.now() - t < 36e5));
    if (R.length >= 10) return send(res, 429, { error: 'ثبت‌نام‌های زیادی از این شبکه شده؛ کمی بعد دوباره امتحان کنید' });
    const u = String(b.username || '').trim().toLowerCase(), n = String(b.name || '').trim().slice(0, 60), pw = String(b.password || '');
    if (!n) return send(res, 400, { error: 'نام را وارد کنید' });
    if (!/^[a-z0-9_.]{3,30}$/.test(u)) return send(res, 400, { error: 'نام کاربری: ۳ تا ۳۰ حرف/عدد انگلیسی (یا شماره موبایل)' });
    if (pw.length < 6) return send(res, 400, { error: 'رمز حداقل ۶ کاراکتر باشد' });
    if (db.prepare('SELECT 1 x FROM users WHERE username=?').get(u)) return send(res, 409, { error: 'این نام کاربری قبلاً گرفته شده؛ نام دیگری انتخاب کنید' });
    if (db.prepare("SELECT COUNT(*) c FROM users WHERE role='pending'").get().c >= 200) return send(res, 429, { error: 'ظرفیت درخواست‌ها پر است؛ با کارفرما تماس بگیرید' });
    R.push(Date.now());
    const role = process.env.AUTO_APPROVE === '1' ? 'worker' : 'pending';
    setUser(u, n, role, pw);
    return send(res, 200, { token: sign(u), role, name: n, username: u });
  }
  if (p === '/api/login') {
    const ip = ipOf(req), F = (fails[ip] = (fails[ip] || []).filter(t => Date.now() - t < 6e5));
    if (F.length >= 10) return send(res, 429, { error: 'تلاش بیش از حد؛ چند دقیقه بعد دوباره امتحان کنید' });
    const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(b.username || '').trim().toLowerCase());
    if (!u || hash(String(b.password || ''), u.salt) !== u.hash) { F.push(Date.now()); return send(res, 401, { error: 'نام کاربری یا رمز اشتباه است' }); }
    return send(res, 200, { token: sign(u.username), role: u.role, name: u.name, username: u.username });
  }
  const me = verify((req.headers.authorization || '').replace('Bearer ', ''));
  if (!me) return send(res, 401, { error: 'ورود لازم است' });

  if (p === '/api/sync' && me.role === 'worker') {   // دریافت آمار از برنامه‌ی کارگر
    const recs = Array.isArray(b.records) ? b.records : [], del = Array.isArray(b.deleted) ? b.deleted : [];
    const UP = 'INSERT INTO records VALUES(?,?,?,?,?,?,?) ON CONFLICT(worker,id) DO UPDATE SET updated=excluded.updated,data=excluded.data,month=excluded.month,qty=excluded.qty,total=excluded.total WHERE excluded.updated>=records.updated';
    const list = [];
    for (const r of recs) { if (!r || !r.id) continue; const { photo, ...d } = r;
      list.push([UP, [me.username, String(r.id), num(r.updatedAt), JSON.stringify(d), String(r.monthKey || ''), num(r.quantity), num(r.totalPrice)]]); }
    for (const id of del) list.push(['DELETE FROM records WHERE worker=? AND id=?', [me.username, String(id)]]);
    list.push(['UPDATE users SET last_sync=? WHERE username=?', [Date.now(), me.username]]);
    try { db.batch(list); } catch (e) { return send(res, 500, { error: String(e) }); }
    return send(res, 200, { ok: true, count: recs.length });
  }
  if (p === '/api/my-orders' && me.role === 'worker') return send(res, 200, db.prepare('SELECT id,title,qty,due,status,note FROM orders WHERE worker=? ORDER BY id DESC').all(me.username));
  if (p === '/api/me') return send(res, 200, me);
  if (me.role !== 'admin') return send(res, 403, { error: 'دسترسی ندارید' });

  if (p === '/api/pending' && req.method === 'GET') return send(res, 200, db.prepare("SELECT username,name FROM users WHERE role='pending' ORDER BY rowid DESC").all());
  if (p.startsWith('/api/pending/') && req.method === 'POST') {   // تأیید
    db.prepare("UPDATE users SET role='worker' WHERE username=? AND role='pending'").run(decodeURIComponent(p.split('/')[3])); return send(res, 200, { ok: true }); }
  if (p.startsWith('/api/pending/') && req.method === 'DELETE') {   // رد
    db.prepare("DELETE FROM users WHERE username=? AND role='pending'").run(decodeURIComponent(p.split('/')[3])); return send(res, 200, { ok: true }); }
  if (p === '/api/workers' && req.method === 'GET')
    return send(res, 200, db.prepare(`SELECT u.username,u.name,u.last_sync,COUNT(r.id) records,COALESCE(SUM(r.qty),0) qty,COALESCE(SUM(r.total),0) total,(SELECT COALESCE(SUM(amount),0) FROM payments p WHERE p.worker=u.username) paid FROM users u LEFT JOIN records r ON r.worker=u.username WHERE u.role='worker' GROUP BY u.username ORDER BY u.username`).all());
  if (p === '/api/workers' && req.method === 'POST') {
    const u = String(b.username || '').trim().toLowerCase();
    if (!/^[a-z0-9_.]{3,30}$/.test(u) || String(b.password || '').length < 4) return send(res, 400, { error: 'نام کاربری (۳ تا ۳۰ حرف/عدد انگلیسی) و رمز (حداقل ۴ کاراکتر) لازم است' });
    const ex = db.prepare('SELECT role FROM users WHERE username=?').get(u);
    if (ex && ex.role !== 'worker') return send(res, 400, { error: 'این نام کاربری مجاز نیست' });
    setUser(u, String(b.name || u), 'worker', String(b.password)); return send(res, 200, { ok: true });
  }
  if (p.startsWith('/api/workers/') && req.method === 'DELETE') {
    const u = decodeURIComponent(p.split('/')[3]);
    db.prepare("DELETE FROM users WHERE username=? AND role='worker'").run(u);
    if (b.purge || url.searchParams.get('purge')) db.prepare('DELETE FROM records WHERE worker=?').run(u);
    return send(res, 200, { ok: true });
  }
  if (p === '/api/records') {
    const w = url.searchParams.get('worker'), m = url.searchParams.get('month');
    const rows = db.prepare('SELECT worker,data FROM records WHERE (? IS NULL OR worker=?) AND (? IS NULL OR month=?) ORDER BY updated DESC LIMIT 5000').all(w || null, w || null, m || null, m || null);
    return send(res, 200, rows.map(r => ({ worker: r.worker, ...JSON.parse(r.data) })));
  }
  if (p === '/api/password' && req.method === 'POST') {
    const u = db.prepare('SELECT * FROM users WHERE username=?').get(me.username);
    if (hash(String(b.old || ''), u.salt) !== u.hash) return send(res, 400, { error: 'رمز فعلی اشتباه است' });
    if (String(b.new || '').length < 6) return send(res, 400, { error: 'رمز جدید حداقل ۶ کاراکتر باشد' });
    setUser(u.username, u.name, u.role, String(b.new)); return send(res, 200, { ok: true }); }
  const mid = () => +p.split('/')[3];
  if (p === '/api/payments' && req.method === 'GET') return send(res, 200, db.prepare('SELECT * FROM payments WHERE (? IS NULL OR worker=?) ORDER BY id DESC').all(url.searchParams.get('worker') || null, url.searchParams.get('worker') || null));
  if (p === '/api/payments' && req.method === 'POST') {
    if (!b.worker || !(num(b.amount) > 0)) return send(res, 400, { error: 'کارگر و مبلغ لازم است' });
    db.prepare('INSERT INTO payments(worker,amount,date,note,created) VALUES(?,?,?,?,?)').run(String(b.worker), num(b.amount), String(b.date || ''), String(b.note || ''), Date.now()); return send(res, 200, { ok: true }); }
  if (p.startsWith('/api/payments/') && req.method === 'DELETE') { db.prepare('DELETE FROM payments WHERE id=?').run(mid()); return send(res, 200, { ok: true }); }
  if (p === '/api/orders' && req.method === 'GET') return send(res, 200, db.prepare('SELECT * FROM orders ORDER BY id DESC').all());
  if (p === '/api/orders' && req.method === 'POST') {
    if (!b.worker || !String(b.title || '').trim()) return send(res, 400, { error: 'کارگر و عنوان سفارش لازم است' });
    db.prepare('INSERT INTO orders(worker,title,qty,due,note,created) VALUES(?,?,?,?,?,?)').run(String(b.worker), String(b.title), num(b.qty), String(b.due || ''), String(b.note || ''), Date.now()); return send(res, 200, { ok: true }); }
  if (p.startsWith('/api/orders/') && req.method === 'PUT') { if (!['new', 'doing', 'done'].includes(b.status)) return send(res, 400, { error: 'وضعیت نامعتبر' }); db.prepare('UPDATE orders SET status=? WHERE id=?').run(b.status, mid()); return send(res, 200, { ok: true }); }
  if (p.startsWith('/api/orders/') && req.method === 'DELETE') { db.prepare('DELETE FROM orders WHERE id=?').run(mid()); return send(res, 200, { ok: true }); }
  if (p === '/api/months') return send(res, 200, db.prepare("SELECT DISTINCT month,COUNT(*) n FROM records WHERE month!='' GROUP BY month ORDER BY month DESC").all());
  send(res, 404, { error: 'not found' });
}).listen(PORT, () => console.log('کارفرما روی http://localhost:' + PORT));
