// POST /api/acct/recover   (Authorization: Bearer <Google ID token>)   body: {"number":"...","code":"<recovery code from the admin>","pin":"new PIN"}
// Used after the admin reset the PIN or the Google link of an account: the owner signs in again and sets a PIN.
import { handler, json, HttpError, readJson, getDoc, commit, write, mustCommit, timingSafeEqual, verifyIdToken } from '../../_lib/fb.js';
import { accountByUid, cleanNumber, cleanNewPassword, hashPin, rid, suspension, suspendedError } from '../../_lib/vip.js';

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  const { uid, email } = await verifyIdToken(env, request);
  const b = await readJson(request), number = cleanNumber(b.number), code = String(b.code || '').trim(), pin = cleanNewPassword(b.pin);
  const acc = await getDoc(env, `vipAccounts/${number}`);
  if (!acc || !acc.recovery || !code || !timingSafeEqual(acc.recovery, code)) throw new HttpError(401, 'Wrong number or recovery code');
  const susp = suspension(acc); if (susp) throw suspendedError(susp);
  if (acc.googleUid && acc.googleUid !== uid) throw new HttpError(403, 'This account is linked to another Google account');
  const other = await accountByUid(env, uid);
  if (other && other.number !== number) throw new HttpError(409, 'This Google account already has another VIP account');
  const salt = rid();
  mustCommit(await commit(env, [write(env, `vipAccounts/${number}`, {
    set: [[['googleUid'], uid], [['googleEmail'], email], [['pinSalt'], salt], [['pinHash'], await hashPin(salt, pin)], [['pinFails'], 0], [['pinLockedUntil'], 0], [['recovery'], '']],
    ts: [['recoveredAt']], exists: true,
  })]), 'Recover');
  return json({ ok: true, number });
});
