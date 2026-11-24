// Shared helpers for the VIP (third app) endpoints.
import { getDoc, getDocMeta, queryEq, commit, write, HttpError, timingSafeEqual, sha256Hex } from './fb.js';

export const NUM_RE = /^\d{6,12}$/;
// 1 USD = 1000 points, always shown with 2 decimals (truncated to whole cents), e.g. 12500 -> $12.50
export const usd = (points) => {
  const cents = Math.floor(Math.max(0, Math.floor(Number(points) || 0)) / 10);
  return '$' + (cents / 100).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
};
export const rid = () => crypto.randomUUID().replace(/-/g, '').slice(0, 20);
export const cleanNumber = (v) => {
  const n = String(v == null ? '' : v).trim();
  if (!NUM_RE.test(n)) throw new HttpError(400, 'Invalid number');
  return n;
};
// Login: lenient (also accepts the older 4-8 digit PINs). Creation: cleanNewPassword (6-32 characters).
export const cleanPin = (v) => {
  const p = String(v == null ? '' : v);
  if (p.length < 4 || p.length > 64) throw new HttpError(400, 'Enter your password');
  return p;
};
// The fixed 6-digit PIN issued by the admin together with the account number.
export const PIN6_RE = /^\d{6}$/;
export const cleanPin6 = (v) => {
  const p = String(v == null ? '' : v).trim();
  if (!PIN6_RE.test(p)) throw new HttpError(400, 'Enter the 6-digit PIN');
  return p;
};
export const cleanNewPassword = (v) => {
  const p = String(v == null ? '' : v);
  if (p.length < 6 || p.length > 32) throw new HttpError(400, 'Password must be 6 to 32 characters');
  return p;
};
export const cleanText = (v, min, max, what) => {
  const t = String(v == null ? '' : v).replace(/[\u0000-\u001f<>]/g, '').replace(/\s+/g, ' ').trim();
  if (t.length < min) throw new HttpError(400, `Please enter ${what}`);
  if (t.length > max) throw new HttpError(400, `${what} is too long`);
  return t;
};
export async function vipSettings(env) {
  const s = (await getDoc(env, 'settings/acct')) || {};
  return { enabled: s.enabled !== false };
}
export const tsMs = (v) => (v ? Date.parse(v) || 0 : 0);
export const byNewest = (a, b) => tsMs(b.createdAt) - tsMs(a.createdAt);
// Firestore commit conflicts (document changed between read and write) are retried by callers.
export const isConflict = (r) => r.status === 409 || r.status === 404 || (r.body && r.body.error && ['ABORTED', 'FAILED_PRECONDITION', 'NOT_FOUND'].includes(r.body.error.status));

export const SUSPENDED = 'This account is suspended by the admin';
/** null when the account is usable, otherwise {reason, until(ms, 0 = until the admin lifts it)} */
export function suspension(acc, now = Date.now()) {
  if (acc.enabled === false) return { reason: String(acc.banReason || ''), until: 0 };
  const until = Number(acc.bannedUntil) || 0;
  if (acc.banned === true && (!until || now < until)) return { reason: String(acc.banReason || ''), until };
  return null;
}
export const suspendedError = (s) => new HttpError(403, SUSPENDED, { suspended: true, reason: s.reason, until: s.until });

export const hashPin = (salt, pin) => sha256Hex(`${salt}:${pin}`);
export async function accountByUid(env, uid) {
  const r = await queryEq(env, 'vipAccounts', 'googleUid', uid, 2);
  return r.length ? { number: r[0].id, acc: r[0].data } : null;
}
const MAX_FAILS = 5, LOCK_MS = 15 * 60 * 1000;
/** Verifies the PIN of a loaded account (with lock-out after 5 wrong attempts). */
export async function checkPin(env, number, acc, pin, numberOk = true) {
  const now = Date.now();
  if (Number(acc.pinLockedUntil) > now) throw new HttpError(429, `Too many wrong attempts. Try again in ${Math.ceil((acc.pinLockedUntil - now) / 60000)} min`);
  if (!acc.pinHash || !acc.pinSalt) throw new HttpError(409, 'This account needs to be recovered first', { recover: true });
  const pinOk = timingSafeEqual(acc.pinHash, await hashPin(acc.pinSalt, pin));
  if (pinOk && numberOk) {
    if (Number(acc.pinFails) > 0) await commit(env, [write(env, `vipAccounts/${number}`, { set: [[['pinFails'], 0]], exists: true })]);
    return;
  }
  const fails = (Number(acc.pinFails) || 0) + 1;
  await commit(env, [write(env, `vipAccounts/${number}`, { set: [[['pinFails'], fails >= MAX_FAILS ? 0 : fails], [['pinLockedUntil'], fails >= MAX_FAILS ? now + LOCK_MS : 0]], exists: true })]);
  throw new HttpError(401, fails >= MAX_FAILS ? 'Too many wrong attempts. Locked for 15 minutes' : 'Wrong number or password');
}
export { getDocMeta };

/* ---- categories (wallet types) managed by the admin in vipMethods; "Personal" is built in and needs no ID ---- */
export const PERSONAL = { id: 'personal', name: 'Personal', requiresId: false, idLabel: '' };
export const NONE = { id: 'none', name: 'None', requiresId: false, idLabel: '' };
export async function listMethods(env) {
  const rows = await queryEq(env, 'vipMethods', 'kind', 'method', 200);
  const m = rows.filter((x) => x.data.enabled !== false && x.data.name)
    .map((x) => ({ id: x.id, name: String(x.data.name), requiresId: x.data.requiresId !== false, idLabel: String(x.data.idLabel || ''), order: Number(x.data.order) || 0 }))
    .sort((a, b) => a.order - b.order || a.name.localeCompare(b.name));
  return [PERSONAL, NONE, ...m.map(({ order, ...r }) => r)];
}
/** Resolves the chosen category and its ID (wallet number); throws friendly errors. */
export async function pickMethod(env, methodId, walletNumber) {
  const id = String(methodId || '');
  const m = (await listMethods(env)).find((x) => x.id === id);
  if (!m) throw new HttpError(400, 'Please choose a category');
  const wn = m.requiresId ? cleanText(walletNumber, 1, 80, 'the ' + (m.idLabel || 'ID number')) : '';
  return { method: m, walletNumber: wn };
}
