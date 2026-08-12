const base = 'http://localhost:4173';
const email = `test-${Date.now()}@example.com`;
const password = 'secret-pass-123';
let token;
let vaultToken;

async function call(path, options = {}) {
  const response = await fetch(base + path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(vaultToken ? { 'X-Vault-Token': vaultToken } : {}) }
  });
  const data = await response.json();
  if (!response.ok) throw new Error(`${path}: ${data.error}`);
  return data;
}

function assert(value, message) { if (!value) throw new Error(message); }

(async () => {
  const signup = await call('/api/signup', { method: 'POST', body: JSON.stringify({ name: '테스트 사용자', email, password }) });
  token = signup.token;
  await call('/api/links', { method: 'POST', body: JSON.stringify({ url: 'https://example.com/public', title: '공개 링크', note: '', tags: ['공개'], secret: false }) });
  await call('/api/links', { method: 'POST', body: JSON.stringify({ url: 'https://example.com/private', title: '비밀 링크', note: '감춰진 메모', tags: ['비밀'], secret: true }) });
  const locked = await call('/api/links');
  assert(locked.links.length === 2, '링크 수가 맞지 않습니다.');
  assert(locked.links.find(x => x.secret).locked === true, '잠긴 목록에서 비밀 링크가 노출됐습니다.');
  assert(!JSON.stringify(locked).includes('감춰진 메모'), '잠긴 응답에 비밀 메모가 포함됐습니다.');
  const blockedReveal = await call('/api/links?reveal=secret');
  assert(blockedReveal.links.find(x => x.secret).locked === true, '전용 토큰 없이 비밀 링크가 노출됐습니다.');
  vaultToken = (await call('/api/vault/unlock', { method: 'POST', body: JSON.stringify({ password }) })).vaultToken;
  const revealed = await call('/api/links?reveal=secret');
  assert(revealed.links.find(x => x.secret).title === '비밀 링크', '잠금 해제 후 비밀 링크를 읽지 못했습니다.');
  const recovery = await call('/api/recovery/request', { method: 'POST', body: JSON.stringify({ email }) });
  assert(/^\d{6}$/.test(recovery.devCode), '개발용 복구 코드가 발급되지 않았습니다.');
  await call('/api/recovery/reset', { method: 'POST', body: JSON.stringify({ email, code: recovery.devCode, password: 'changed-pass-123' }) });
  token = undefined;
  const login = await call('/api/login', { method: 'POST', body: JSON.stringify({ email, password: 'changed-pass-123' }) });
  assert(login.token, '변경된 비밀번호로 로그인하지 못했습니다.');
  console.log('PASS: signup, public/secret save, locked response, decrypt, recovery, login');
})().catch(error => { console.error('FAIL:', error.message); process.exitCode = 1; });
