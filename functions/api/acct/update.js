// POST /api/acct/update   (Authorization: Bearer <Google ID token>)
// body: {"number","password" (current), "name"?, "methodId"?, "walletNumber"?, "newPassword"?}   - change name, category/ID and/or password from the app settings.
import { handler, json, HttpError, readJson, commit, write, mustCommit, verifyIdToken } from '../../_lib/fb.js';
import { accountByUid, checkPin, cleanPin, cleanNewPassword, cleanText, hashPin, rid, suspension, suspendedError, pickMethod } from '../../_lib/vip.js';

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  const { uid } = await verifyIdToken(env, request);
  const found = await accountByUid(env, uid);
  if (!found) throw new HttpError(404, 'No account for this Google account');
  const { number, acc } = found;
  const susp = suspension(acc); if (susp) throw suspendedError(susp);
  const b = await readJson(request);
  await checkPin(env, number, acc, cleanPin(b.password), String(b.number || '').trim() === number);
  const set = [];
  if (b.name !== undefined && String(b.name).trim() !== '') set.push([['name'], cleanText(b.name, 2, 40, 'your name')]);
  if (b.methodId !== undefined && b.methodId !== '') {
    const { method, walletNumber } = await pickMethod(env, b.methodId, b.walletNumber);
    set.push([['method'], method.name], [['methodId'], method.id], [['walletNumber'], walletNumber]);
  }
  if (b.newPassword) { const salt = rid(); set.push([['pinSalt'], salt], [['pinHash'], await hashPin(salt, cleanNewPassword(b.newPassword))]); }
  if (!set.length) throw new HttpError(400, 'Nothing to change');
  mustCommit(await commit(env, [write(env, `vipAccounts/${number}`, { set, ts: [['updatedAt']], exists: true })]), 'Update');
  return json({ ok: true });
});
