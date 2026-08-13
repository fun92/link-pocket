const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PORT = Number(process.env.PORT || 4173);
const APP_SECRET = process.env.APP_SECRET || 'development-only-secret-change-before-deploying';
const sessions = new Map();
const vaultSessions = new Map();
const resetCodes = new Map();

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], links: [] }, null, 2));

function db() { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
function save(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }
function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}
function body(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; if (raw.length > 1e6) reject(new Error('too large')); });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('invalid json')); } });
  });
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, original] = stored.split(':');
  const attempt = hashPassword(password, salt).split(':')[1];
  return crypto.timingSafeEqual(Buffer.from(original, 'hex'), Buffer.from(attempt, 'hex'));
}
function keyFor(userId) { return crypto.scryptSync(APP_SECRET, `vault:${userId}`, 32); }
function encrypt(value, userId) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyFor(userId), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: encrypted.toString('base64') };
}
function decrypt(value, userId) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyFor(userId), Buffer.from(value.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(value.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(value.data, 'base64')), decipher.final()]).toString('utf8'));
}
function token(req) { return (req.headers.authorization || '').replace(/^Bearer /, ''); }
function currentUser(req) { const id = sessions.get(token(req)); return id ? db().users.find(u => u.id === id) : null; }
function vaultAuthorized(req, userId) {
  const record = vaultSessions.get(req.headers['x-vault-token']);
  return Boolean(record && record.userId === userId && record.expires > Date.now());
}
function safeUser(user) { return { id: user.id, email: user.email, name: user.name }; }
function cleanLink(link, userId, revealSecret = false) {
  const base = { id: link.id, secret: link.secret, favorite: link.favorite, createdAt: link.createdAt };
  if (link.secret && !revealSecret) return { ...base, locked: true };
  const content = link.secret ? decrypt(link.content, userId) : link.content;
  return { ...base, ...content };
}
function randomToken() { return crypto.randomBytes(32).toString('hex'); }
function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }

async function sendResetEmail(email, code) {
  if (!process.env.RESEND_API_KEY) return false;
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM || 'Link Pocket <onboarding@resend.dev>',
      to: [email], subject: 'Link Pocket 비밀번호 재설정 코드',
      html: `<div style="font-family:sans-serif;padding:24px"><h2>비밀번호 재설정</h2><p>아래 코드는 10분 동안 유효합니다.</p><p style="font-size:30px;letter-spacing:8px;font-weight:700">${code}</p><p>요청하지 않았다면 이 메일을 무시하세요.</p></div>`
    })
  });
  if (!response.ok) throw new Error('email delivery failed');
  return true;
}

async function api(req, res, route) {
  try {
    if (route === '/api/signup' && req.method === 'POST') {
      const input = await body(req); const email = normalizeEmail(input.email);
      if (!email.includes('@') || String(input.password || '').length < 8) return json(res, 400, { error: '이메일과 8자 이상의 비밀번호를 입력해주세요.' });
      const data = db(); if (data.users.some(u => u.email === email)) return json(res, 409, { error: '이미 가입된 이메일입니다.' });
      const user = { id: crypto.randomUUID(), email, name: String(input.name || '').trim() || '링크 수집가', password: hashPassword(input.password), createdAt: new Date().toISOString() };
      data.users.push(user); save(data); const session = randomToken(); sessions.set(session, user.id);
      return json(res, 201, { token: session, user: safeUser(user) });
    }
    if (route === '/api/login' && req.method === 'POST') {
      const input = await body(req); const data = db(); const user = data.users.find(u => u.email === normalizeEmail(input.email));
      if (!user || !verifyPassword(String(input.password || ''), user.password)) return json(res, 401, { error: '이메일 또는 비밀번호가 맞지 않습니다.' });
      const session = randomToken(); sessions.set(session, user.id); return json(res, 200, { token: session, user: safeUser(user) });
    }
    if (route === '/api/recovery/request' && req.method === 'POST') {
      const input = await body(req); const email = normalizeEmail(input.email); const user = db().users.find(u => u.email === email);
      let devCode;
      if (user) {
        const code = String(crypto.randomInt(100000, 1000000));
        resetCodes.set(email, { hash: crypto.createHash('sha256').update(code).digest('hex'), expires: Date.now() + 10 * 60 * 1000, attempts: 0 });
        const sent = await sendResetEmail(email, code);
        if (!sent && process.env.NODE_ENV !== 'production') devCode = code;
      }
      return json(res, 200, { ok: true, devCode, message: '가입된 이메일이라면 재설정 코드를 보냈습니다.' });
    }
    if (route === '/api/recovery/reset' && req.method === 'POST') {
      const input = await body(req); const email = normalizeEmail(input.email); const record = resetCodes.get(email);
      if (!record || record.expires < Date.now() || record.attempts >= 5) return json(res, 400, { error: '코드가 만료되었거나 유효하지 않습니다.' });
      record.attempts += 1; const candidate = crypto.createHash('sha256').update(String(input.code || '')).digest('hex');
      if (!crypto.timingSafeEqual(Buffer.from(record.hash), Buffer.from(candidate))) return json(res, 400, { error: '코드가 맞지 않습니다.' });
      if (String(input.password || '').length < 8) return json(res, 400, { error: '새 비밀번호는 8자 이상이어야 합니다.' });
      const data = db(); const user = data.users.find(u => u.email === email); if (!user) return json(res, 400, { error: '계정을 찾을 수 없습니다.' });
      user.password = hashPassword(input.password); save(data); resetCodes.delete(email);
      for (const [key, id] of sessions) if (id === user.id) sessions.delete(key);
      return json(res, 200, { ok: true });
    }
    const user = currentUser(req); if (!user) return json(res, 401, { error: '로그인이 필요합니다.' });
    if (route === '/api/me' && req.method === 'GET') return json(res, 200, { user: safeUser(user) });
    if (route === '/api/vault/unlock' && req.method === 'POST') {
      const input = await body(req);
      if (!verifyPassword(String(input.password || ''), user.password)) return json(res, 401, { error: '비밀번호가 맞지 않습니다.' });
      const vaultToken = randomToken(); vaultSessions.set(vaultToken, { userId: user.id, expires: Date.now() + 3 * 60 * 1000 });
      return json(res, 200, { vaultToken, expiresIn: 180 });
    }
    if (route === '/api/links' && req.method === 'GET') {
      const wantsReveal = new URL(req.url, `http://${req.headers.host}`).searchParams.get('reveal') === 'secret';
      const reveal = wantsReveal && vaultAuthorized(req, user.id);
      return json(res, 200, { links: db().links.filter(l => l.userId === user.id).map(l => cleanLink(l, user.id, reveal)) });
    }
    if (route === '/api/links' && req.method === 'POST') {
      const input = await body(req); let parsed; try { parsed = new URL(input.url); } catch { return json(res, 400, { error: '올바른 링크 주소를 입력해주세요.' }); }
      if (!['http:', 'https:'].includes(parsed.protocol)) return json(res, 400, { error: 'http 또는 https 링크만 저장할 수 있습니다.' });
      const content = { url: parsed.href, title: String(input.title || parsed.hostname).slice(0, 160), note: String(input.note || '').slice(0, 1000), tags: Array.isArray(input.tags) ? input.tags.slice(0, 8) : [] };
      const link = { id: crypto.randomUUID(), userId: user.id, secret: Boolean(input.secret), favorite: false, content: input.secret ? encrypt(content, user.id) : content, createdAt: new Date().toISOString() };
      const data = db(); data.links.unshift(link); save(data); return json(res, 201, { link: cleanLink(link, user.id, true) });
    }
    const match = route.match(/^\/api\/links\/([^/]+)$/);
    if (match && req.method === 'PATCH') {
      const data = db(); const link = data.links.find(l => l.id === match[1] && l.userId === user.id); if (!link) return json(res, 404, { error: '링크를 찾을 수 없습니다.' });
      const input = await body(req); if (typeof input.favorite === 'boolean') link.favorite = input.favorite; save(data); return json(res, 200, { link: cleanLink(link, user.id, true) });
    }
    if (match && req.method === 'DELETE') {
      const data = db(); const index = data.links.findIndex(l => l.id === match[1] && l.userId === user.id); if (index < 0) return json(res, 404, { error: '링크를 찾을 수 없습니다.' });
      data.links.splice(index, 1); save(data); return json(res, 200, { ok: true });
    }
    return json(res, 404, { error: '요청을 찾을 수 없습니다.' });
  } catch (error) { console.error(error); return json(res, 500, { error: '처리 중 문제가 생겼습니다.' }); }
}

const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json', '.shortcut': 'application/octet-stream' };
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`); if (url.pathname.startsWith('/api/')) return api(req, res, url.pathname);
  const requested = url.pathname === '/' ? '/index.html' : url.pathname; const file = path.normalize(path.join(PUBLIC, requested));
  if (!file.startsWith(PUBLIC)) return res.writeHead(403).end();
  fs.readFile(file, (error, content) => { if (error) { res.writeHead(404); return res.end('Not found'); } res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' }); res.end(content); });
});
server.listen(PORT, () => console.log(`Link Pocket is running at http://localhost:${PORT}`));
