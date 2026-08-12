import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

const APP_SECRET = process.env.APP_SECRET;
const production = process.env.NODE_ENV === 'production' || Boolean(process.env.NETLIFY);

function response(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
}
function store() { return getStore({ name: 'link-pocket', consistency: 'strong' }); }
async function readDb() { return (await store().get('database', { type: 'json' })) || { users: [], links: [] }; }
async function saveDb(data) { await store().set('database', JSON.stringify(data)); }
function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}
function verifyPassword(password, stored = '') {
  try {
    const [salt, original] = stored.split(':');
    const attempt = hashPassword(password, salt).split(':')[1];
    return crypto.timingSafeEqual(Buffer.from(original, 'hex'), Buffer.from(attempt, 'hex'));
  } catch { return false; }
}
function requireSecret() {
  if (!APP_SECRET || APP_SECRET.length < 32) throw new Error('APP_SECRET_MISSING');
  return APP_SECRET;
}
function sign(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', requireSecret()).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}
function verifyToken(value, type) {
  try {
    const [encoded, signature] = String(value || '').split('.');
    const expected = crypto.createHmac('sha256', requireSecret()).update(encoded).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    return payload.type === type && payload.exp > Date.now() ? payload : null;
  } catch { return null; }
}
function sessionFor(user) { return sign({ sub: user.id, ver: user.sessionVersion || 0, type: 'session', exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }); }
function keyFor(userId) { return crypto.scryptSync(requireSecret(), `vault:${userId}`, 32); }
function encrypt(value, userId) {
  const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv('aes-256-gcm', keyFor(userId), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: encrypted.toString('base64') };
}
function decrypt(value, userId) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyFor(userId), Buffer.from(value.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(value.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(value.data, 'base64')), decipher.final()]).toString('utf8'));
}
function cleanLink(link, userId, reveal = false) {
  const base = { id: link.id, secret: link.secret, favorite: link.favorite, createdAt: link.createdAt };
  if (link.secret && !reveal) return { ...base, locked: true };
  return { ...base, ...(link.secret ? decrypt(link.content, userId) : link.content) };
}
function safeUser(user) { return { id: user.id, email: user.email, name: user.name }; }
async function input(req) { try { return await req.json(); } catch { return {}; } }
async function sendResetEmail(email, code) {
  if (!process.env.RESEND_API_KEY) return false;
  const sent = await fetch('https://api.resend.com/emails', {
    method: 'POST', headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: process.env.EMAIL_FROM || 'Link Pocket <onboarding@resend.dev>', to: [email], subject: 'Link Pocket 비밀번호 재설정 코드', html: `<div style="font-family:sans-serif;padding:24px"><h2>비밀번호 재설정</h2><p>아래 코드는 10분 동안 유효합니다.</p><p style="font-size:30px;letter-spacing:8px;font-weight:700">${code}</p><p>요청하지 않았다면 이 메일을 무시하세요.</p></div>` })
  });
  if (!sent.ok) throw new Error('EMAIL_FAILED'); return true;
}

export default async (req) => {
  try {
    requireSecret();
    const url = new URL(req.url);
    const path = url.pathname
      .replace(/^\/\.netlify\/functions\/api/, '')
      .replace(/^\/api/, '') || '/';
    const method = req.method;
    if (path === '/signup' && method === 'POST') {
      const data = await readDb(); const body = await input(req); const email = normalizeEmail(body.email);
      if (!email.includes('@') || String(body.password || '').length < 8) return response(400, { error: '이메일과 8자 이상의 비밀번호를 입력해주세요.' });
      if (data.users.some(user => user.email === email)) return response(409, { error: '이미 가입된 이메일입니다.' });
      const user = { id: crypto.randomUUID(), email, name: String(body.name || '').trim() || '링크 수집가', password: hashPassword(body.password), createdAt: new Date().toISOString() };
      data.users.push(user); await saveDb(data); return response(201, { token: sessionFor(user), user: safeUser(user) });
    }
    if (path === '/login' && method === 'POST') {
      const body = await input(req); const user = (await readDb()).users.find(item => item.email === normalizeEmail(body.email));
      if (!user || !verifyPassword(String(body.password || ''), user.password)) return response(401, { error: '이메일 또는 비밀번호가 맞지 않습니다.' });
      return response(200, { token: sessionFor(user), user: safeUser(user) });
    }
    if (path === '/recovery/request' && method === 'POST') {
      const body = await input(req); const email = normalizeEmail(body.email); const data = await readDb(); const user = data.users.find(item => item.email === email); let devCode;
      if (user) {
        const code = String(crypto.randomInt(100000, 1000000));
        await store().set(`recovery-${crypto.createHash('sha256').update(email).digest('hex')}`, JSON.stringify({ hash: crypto.createHash('sha256').update(code).digest('hex'), expires: Date.now() + 10 * 60 * 1000, attempts: 0 }));
        const sent = await sendResetEmail(email, code); if (!sent && !production) devCode = code;
      }
      return response(200, { ok: true, devCode, message: '가입된 이메일이라면 재설정 코드를 보냈습니다.' });
    }
    if (path === '/recovery/reset' && method === 'POST') {
      const body = await input(req); const email = normalizeEmail(body.email); const recoveryStore = store(); const key = `recovery-${crypto.createHash('sha256').update(email).digest('hex')}`; const record = await recoveryStore.get(key, { type: 'json' });
      if (!record || record.expires < Date.now() || record.attempts >= 5) return response(400, { error: '코드가 만료되었거나 유효하지 않습니다.' });
      record.attempts += 1; await recoveryStore.set(key, JSON.stringify(record));
      const candidate = crypto.createHash('sha256').update(String(body.code || '')).digest('hex');
      if (!crypto.timingSafeEqual(Buffer.from(record.hash), Buffer.from(candidate))) return response(400, { error: '코드가 맞지 않습니다.' });
      if (String(body.password || '').length < 8) return response(400, { error: '새 비밀번호는 8자 이상이어야 합니다.' });
      const data = await readDb(); const user = data.users.find(item => item.email === email); if (!user) return response(400, { error: '계정을 찾을 수 없습니다.' });
      user.password = hashPassword(body.password); user.sessionVersion = (user.sessionVersion || 0) + 1; await saveDb(data); await recoveryStore.delete(key); return response(200, { ok: true });
    }
    const auth = verifyToken((req.headers.get('authorization') || '').replace(/^Bearer /, ''), 'session');
    if (!auth) return response(401, { error: '로그인이 필요합니다.' });
    const data = await readDb(); const user = data.users.find(item => item.id === auth.sub); if (!user || (user.sessionVersion || 0) !== auth.ver) return response(401, { error: '로그인이 필요합니다.' });
    if (path === '/me' && method === 'GET') return response(200, { user: safeUser(user) });
    if (path === '/vault/unlock' && method === 'POST') {
      const body = await input(req); if (!verifyPassword(String(body.password || ''), user.password)) return response(401, { error: '비밀번호가 맞지 않습니다.' });
      return response(200, { vaultToken: sign({ sub: user.id, type: 'vault', exp: Date.now() + 3 * 60 * 1000 }), expiresIn: 180 });
    }
    if (path === '/links' && method === 'GET') {
      const vault = verifyToken(req.headers.get('x-vault-token'), 'vault'); const reveal = url.searchParams.get('reveal') === 'secret' && vault?.sub === user.id;
      return response(200, { links: data.links.filter(link => link.userId === user.id).map(link => cleanLink(link, user.id, reveal)) });
    }
    if (path === '/links' && method === 'POST') {
      const body = await input(req); let parsed; try { parsed = new URL(body.url); } catch { return response(400, { error: '올바른 링크 주소를 입력해주세요.' }); }
      if (!['http:', 'https:'].includes(parsed.protocol)) return response(400, { error: 'http 또는 https 링크만 저장할 수 있습니다.' });
      const content = { url: parsed.href, title: String(body.title || parsed.hostname).slice(0, 160), note: String(body.note || '').slice(0, 1000), tags: Array.isArray(body.tags) ? body.tags.slice(0, 8) : [] };
      const link = { id: crypto.randomUUID(), userId: user.id, secret: Boolean(body.secret), favorite: false, content: body.secret ? encrypt(content, user.id) : content, createdAt: new Date().toISOString() };
      data.links.unshift(link); await saveDb(data); return response(201, { link: cleanLink(link, user.id, true) });
    }
    const match = path.match(/^\/links\/([^/]+)$/);
    if (match && method === 'PATCH') {
      const link = data.links.find(item => item.id === match[1] && item.userId === user.id); if (!link) return response(404, { error: '링크를 찾을 수 없습니다.' });
      const body = await input(req); if (typeof body.favorite === 'boolean') link.favorite = body.favorite; await saveDb(data); return response(200, { link: cleanLink(link, user.id, true) });
    }
    if (match && method === 'DELETE') {
      const index = data.links.findIndex(item => item.id === match[1] && item.userId === user.id); if (index < 0) return response(404, { error: '링크를 찾을 수 없습니다.' });
      data.links.splice(index, 1); await saveDb(data); return response(200, { ok: true });
    }
    return response(404, { error: '요청을 찾을 수 없습니다.' });
  } catch (error) {
    console.error(error);
    if (error.message === 'APP_SECRET_MISSING') return response(503, { error: '서버 보안 설정이 필요합니다.' });
    if (error.message === 'EMAIL_FAILED') return response(502, { error: '복구 메일을 보내지 못했습니다.' });
    return response(500, { error: '처리 중 문제가 생겼습니다.' });
  }
};
