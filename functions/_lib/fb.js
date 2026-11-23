// Minimal Firebase Admin helpers for Cloudflare Pages Functions (Workers runtime).
// No npm dependencies. Uses a service account (env FIREBASE_SERVICE_ACCOUNT) so that
// all writes made here bypass Firestore rules and cannot be forged by app users.

const te = new TextEncoder();
export const DEFAULT_API_KEY = 'AIzaSyB45rvl6iTjsdiW3-Ka6jyqiFaJmrsUUwI'; // public web API key (same as in the apps)
export const DEFAULT_ADMIN_UID = 'wQgo9HTzP0NWC6JO2D1Di8iIPm62';

export class HttpError extends Error {
  constructor(status, message, extra) { super(message); this.status = status; if (extra) this.extra = extra; }
}

/* ---------- CORS / responses ---------- */
export const cors = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'authorization,content-type',
  'access-control-allow-methods': 'GET,POST,OPTIONS',
  'access-control-max-age': '86400',
};
export const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...cors },
});
export const text = (body, status = 200) => new Response(String(body), {
  status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...cors },
});
export function handler(fn) {
  return async (ctx) => {
    if (ctx.request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    try { return await fn(ctx); }
    catch (e) {
      if (e instanceof HttpError) return json({ ok: false, error: e.message, ...(e.extra || {}) }, e.status);
      console.error('Unhandled error', e);
      return json({ ok: false, error: 'Server error' }, 500);
    }
  };
}

/* ---------- service account + OAuth ---------- */
function b64u(bytes) {
  const a = new Uint8Array(bytes); let s = '';
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const b64uStr = (s) => b64u(te.encode(s));
function pemToDer(pem) {
  const b = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  const bin = atob(b); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
export function serviceAccount(env) {
  if (!env || !env.FIREBASE_SERVICE_ACCOUNT) throw new HttpError(503, 'FIREBASE_SERVICE_ACCOUNT is not configured');
  let sa = env.FIREBASE_SERVICE_ACCOUNT;
  if (typeof sa === 'string') { try { sa = JSON.parse(sa); } catch { throw new HttpError(503, 'FIREBASE_SERVICE_ACCOUNT is not valid JSON'); } }
  if (!sa.client_email || !sa.private_key || !sa.project_id) throw new HttpError(503, 'FIREBASE_SERVICE_ACCOUNT is missing fields');
  return { ...sa, private_key: String(sa.private_key).replace(/\\n/g, '\n') };
}
let tokenCache = { email: '', token: '', exp: 0 };
export async function accessToken(env) {
  const sa = serviceAccount(env), now = Math.floor(Date.now() / 1000);
  if (tokenCache.email === sa.client_email && tokenCache.exp - 60 > now) return tokenCache.token;
  const header = b64uStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = b64uStr(JSON.stringify({
    iss: sa.client_email, sub: sa.client_email, aud: 'https://oauth2.googleapis.com/token',
    scope: 'https://www.googleapis.com/auth/cloud-platform', iat: now, exp: now + 3600,
  }));
  const key = await crypto.subtle.importKey('pkcs8', pemToDer(sa.private_key), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, te.encode(header + '.' + claim));
  const jwt = header + '.' + claim + '.' + b64u(sig);
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + encodeURIComponent(jwt),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok || !j.access_token) throw new HttpError(502, 'Could not get a Google access token: ' + (j.error_description || j.error || res.status));
  tokenCache = { email: sa.client_email, token: j.access_token, exp: now + (Number(j.expires_in) || 3600) };
  return tokenCache.token;
}
async function gfetch(env, url, opts = {}) {
  const token = await accessToken(env);
  const res = await fetch(url, { ...opts, headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json', ...(opts.headers || {}) } });
  const raw = await res.text(); let body = null;
  try { body = raw ? JSON.parse(raw) : null; } catch { body = raw; }
  return { ok: res.ok, status: res.status, body };
}

/* ---------- Firebase Auth ---------- */
export async function verifyIdToken(env, request) {
  const m = (request.headers.get('authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (!m) throw new HttpError(401, 'Missing Authorization bearer token');
  const key = (env && env.FIREBASE_API_KEY) || DEFAULT_API_KEY;
  const res = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + encodeURIComponent(key), {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ idToken: m[1] }),
  });
  const j = await res.json().catch(() => ({}));
  const u = j.users && j.users[0];
  if (!res.ok || !u || !u.localId) throw new HttpError(401, 'Invalid or expired token');
  if (u.disabled) throw new HttpError(403, 'Account disabled');
  return { uid: u.localId, email: u.email || '', name: u.displayName || '' };
}
export async function requireAdmin(env, request) {
  const { uid } = await verifyIdToken(env, request);
  if (uid !== ((env && env.ADMIN_UID) || DEFAULT_ADMIN_UID)) throw new HttpError(403, 'Admin only');
  return uid;
}
export async function deleteAuthUser(env, uid) {
  const sa = serviceAccount(env);
  const r = await gfetch(env, `https://identitytoolkit.googleapis.com/v1/projects/${sa.project_id}/accounts:delete`, {
    method: 'POST', body: JSON.stringify({ localId: uid }),
  });
  if (r.ok) return true;
  const msg = JSON.stringify(r.body || '');
  if (/USER_NOT_FOUND/.test(msg)) return true;
  throw new HttpError(502, 'Could not delete the login account: ' + msg.slice(0, 200));
}

/* ---------- Firestore (REST) ---------- */
const fsRoot = (env) => `projects/${serviceAccount(env).project_id}/databases/(default)`;
export const docName = (env, path) => `${fsRoot(env)}/documents/${path}`;
export const fp = (...segs) => segs.map((s) => '`' + String(s).replace(/\\/g, '\\\\').replace(/`/g, '\\`') + '`').join('.');

export function toFs(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (typeof v === 'string') return { stringValue: v };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toFs) } };
  return { mapValue: { fields: Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toFs(x)])) } };
}
export function fromFs(v) {
  if (!v) return null;
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return Number(v.integerValue);
  if ('doubleValue' in v) return v.doubleValue;
  if ('booleanValue' in v) return v.booleanValue;
  if ('timestampValue' in v) return v.timestampValue;
  if ('nullValue' in v) return null;
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(fromFs);
  if ('mapValue' in v) return fromFields(v.mapValue.fields || {});
  return null;
}
export const fromFields = (f) => Object.fromEntries(Object.entries(f || {}).map(([k, x]) => [k, fromFs(x)]));

export async function getDoc(env, path) {
  const r = await gfetch(env, `https://firestore.googleapis.com/v1/${docName(env, path)}`);
  if (r.status === 404) return null;
  if (!r.ok) throw new HttpError(502, 'Firestore read failed: ' + ((r.body && r.body.error && r.body.error.message) || r.status));
  return fromFields(r.body.fields);
}
export async function getDocMeta(env, path) {
  const r = await gfetch(env, `https://firestore.googleapis.com/v1/${docName(env, path)}`);
  if (r.status === 404) return null;
  if (!r.ok) throw new HttpError(502, 'Firestore read failed: ' + ((r.body && r.body.error && r.body.error.message) || r.status));
  return { data: fromFields(r.body.fields), updateTime: r.body.updateTime };
}
export async function queryEq(env, collectionId, field, value, limit = 500) {
  const r = await gfetch(env, `https://firestore.googleapis.com/v1/${fsRoot(env)}/documents:runQuery`, {
    method: 'POST',
    body: JSON.stringify({ structuredQuery: { from: [{ collectionId }], where: { fieldFilter: { field: { fieldPath: field }, op: 'EQUAL', value: toFs(value) } }, limit } }),
  });
  if (!r.ok) throw new HttpError(502, 'Firestore query failed: ' + ((r.body && r.body[0] && r.body[0].error && r.body[0].error.message) || (r.body && r.body.error && r.body.error.message) || r.status));
  return (r.body || []).filter((x) => x.document).map((x) => ({ id: x.document.name.split('/').pop(), path: x.document.name.split('/documents/')[1], data: fromFields(x.document.fields) }));
}
/** Build one Firestore write. set: [[segs,value]], ts: [segs] (server time), inc: [[segs,number]], exists: true|false|undefined */
export function write(env, path, { set = [], ts = [], inc = [], exists, updateTime } = {}) {
  const fields = {}, mask = [];
  for (const [segs, val] of set) {
    let cur = fields;
    segs.slice(0, -1).forEach((s) => { if (!cur[s]) cur[s] = { mapValue: { fields: {} } }; cur = cur[s].mapValue.fields; });
    cur[segs[segs.length - 1]] = toFs(val);
    mask.push(fp(...segs));
  }
  const w = { update: { name: docName(env, path), fields }, updateMask: { fieldPaths: mask } };
  const tr = [];
  ts.forEach((segs) => tr.push({ fieldPath: fp(...segs), setToServerValue: 'REQUEST_TIME' }));
  inc.forEach(([segs, n]) => tr.push({ fieldPath: fp(...segs), increment: Number.isInteger(n) ? { integerValue: String(n) } : { doubleValue: n } }));
  if (tr.length) w.updateTransforms = tr;
  if (updateTime) w.currentDocument = { updateTime };
  else if (exists !== undefined) w.currentDocument = { exists };
  return w;
}
export const del = (env, path) => ({ delete: docName(env, path) });
export const commit = (env, writes) => gfetch(env, `https://firestore.googleapis.com/v1/${fsRoot(env)}/documents:commit`, { method: 'POST', body: JSON.stringify({ writes }) });
export const isAlreadyExists = (r) => r.status === 409 || (r.body && r.body.error && r.body.error.status === 'ALREADY_EXISTS');
export const isMissing = (r) => r.status === 404 || (r.body && r.body.error && (r.body.error.status === 'NOT_FOUND' || r.body.error.status === 'FAILED_PRECONDITION'));
export function mustCommit(r, what) {
  if (!r.ok) throw new HttpError(502, `${what} failed: ` + ((r.body && r.body.error && r.body.error.message) || r.status));
}

/* ---------- hashing ---------- */
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
export const sha256Hex = async (s) => hex(await crypto.subtle.digest('SHA-256', te.encode(s)));
export async function hmacSha256Hex(key, msg) {
  const k = await crypto.subtle.importKey('raw', te.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, te.encode(msg)));
}
export async function hmacSha1Hex(key, msg) {
  const k = await crypto.subtle.importKey('raw', te.encode(key), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, te.encode(msg)));
}
export function timingSafeEqual(a, b) {
  a = String(a); b = String(b);
  let r = a.length ^ b.length; const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return r === 0;
}
// Pure JS MD5 (many offer-wall providers sign postbacks with MD5)
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0);
const MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
export function md5Hex(str) {
  const bytes = te.encode(str), len = bytes.length, nblk = ((len + 8) >> 6) + 1, w = new Int32Array(nblk * 16);
  for (let i = 0; i < len; i++) w[i >> 2] |= bytes[i] << ((i % 4) * 8);
  w[len >> 2] |= 0x80 << ((len % 4) * 8);
  w[nblk * 16 - 2] = (len * 8) | 0; w[nblk * 16 - 1] = Math.floor(len / 0x20000000);
  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  for (let i = 0; i < w.length; i += 16) {
    let A = a, B = b, C = c, D = d;
    for (let j = 0; j < 64; j++) {
      let f, g;
      if (j < 16) { f = (B & C) | (~B & D); g = j; }
      else if (j < 32) { f = (D & B) | (~D & C); g = (5 * j + 1) % 16; }
      else if (j < 48) { f = B ^ C ^ D; g = (3 * j + 5) % 16; }
      else { f = C ^ (B | ~D); g = (7 * j) % 16; }
      const s = MD5_S[(j >> 4) * 4 + (j % 4)], tmp = D;
      D = C; C = B;
      const x = (A + f + MD5_K[j] + w[i + g]) | 0;
      B = (B + ((x << s) | (x >>> (32 - s)))) | 0;
      A = tmp;
    }
    a = (a + A) | 0; b = (b + B) | 0; c = (c + C) | 0; d = (d + D) | 0;
  }
  const le = (n) => [0, 8, 16, 24].map((sh) => ((n >>> sh) & 255).toString(16).padStart(2, '0')).join('');
  return le(a) + le(b) + le(c) + le(d);
}

/* ---------- small helpers ---------- */
export async function readJson(request) {
  try { return await request.json(); } catch { throw new HttpError(400, 'Invalid JSON body'); }
}
export const isUid = (s) => typeof s === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(s);
export function clientGeo(request) {
  const cf = request.cf || {};
  let country = String(cf.country || request.headers.get('cf-ipcountry') || '').toUpperCase();
  if (!/^[A-Z]{2}$/.test(country) || country === 'XX' || country === 'T1') country = '';
  const ip = String(request.headers.get('cf-connecting-ip') || '').trim().slice(0, 45);
  return { ip, country };
}
