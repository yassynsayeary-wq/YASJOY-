// POST /api/acct/forgot   (Authorization: Bearer <Google ID token>)   body: {"methodId":"...","walletNumber":"the ID registered","password":"new password"}
// "Forgot password": the owner (signed in with the linked Google account) proves the category + ID that are on file, then sets a new password.
// The ID can NOT be changed here - only the admin can change it. Accounts without an ID (Personal) must contact the admin.
import { handler, json, HttpError, readJson, commit, write, mustCommit, timingSafeEqual, verifyIdToken } from '../../_lib/fb.js';
import { accountByUid, cleanNewPassword, hashPin, rid, suspension, suspendedError, listMethods } from '../../_lib/vip.js';

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  const { uid } = await verifyIdToken(env, request);
  const found = await accountByUid(env, uid);
  if (!found) throw new HttpError(404, 'No account for this Google account');
  const { number, acc } = found;
  const susp = suspension(acc); if (susp) throw suspendedError(susp);
  const b = await readJson(request), password = cleanNewPassword(b.password), now = Date.now();
  if (!acc.walletNumber) throw new HttpError(409, 'Your account has no ID on file. Please contact the admin to reset your password.', { contactAdmin: true });
  if (Number(acc.forgotLockedUntil) > now) throw new HttpError(429, `Too many wrong attempts. Try again in ${Math.ceil((acc.forgotLockedUntil - now) / 60000)} min`);
  const m = (await listMethods(env)).find((x) => x.id === String(b.methodId || ''));
  const catOk = !!m && ((acc.methodId && acc.methodId === m.id) || acc.method === m.name);
  const idOk = timingSafeEqual(String(acc.walletNumber).trim().toLowerCase(), String(b.walletNumber || '').trim().toLowerCase());
  if (!(catOk && idOk)) {
    const fails = (Number(acc.forgotFails) || 0) + 1;
    await commit(env, [write(env, `vipAccounts/${number}`, { set: [[['forgotFails'], fails >= 5 ? 0 : fails], [['forgotLockedUntil'], fails >= 5 ? now + 15 * 60000 : 0]], exists: true })]);
    throw new HttpError(401, fails >= 5 ? 'Too many wrong attempts. Locked for 15 minutes' : 'The category or ID does not match what is registered');
  }
  const salt = rid();
  mustCommit(await commit(env, [write(env, `vipAccounts/${number}`, {
    set: [[['pinSalt'], salt], [['pinHash'], await hashPin(salt, password)], [['pinFails'], 0], [['pinLockedUntil'], 0], [['forgotFails'], 0], [['forgotLockedUntil'], 0], [['recovery'], '']],
    ts: [['passwordResetAt']], exists: true,
  })]), 'Reset password');
  return json({ ok: true, number });
});
