// POST /api/acct/register   (Authorization: Bearer <Google-signed-in Firebase ID token>)
// body: {"number":"<account ID issued by the admin>","name":"Ali","methodId":"personal|<category id>","walletNumber":"(not needed for Personal)","password":"..."}
// Activates an account ID that the admin created in advance. Without a valid unused ID nothing can be created.
import { handler, json, HttpError, readJson, getDocMeta, commit, write, mustCommit, verifyIdToken } from '../../_lib/fb.js';
import { accountByUid, cleanNumber, cleanNewPassword, cleanText, hashPin, rid, pickMethod, isConflict } from '../../_lib/vip.js';

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  const { uid, email } = await verifyIdToken(env, request);
  const b = await readJson(request);
  const number = cleanNumber(b.number);
  const name = cleanText(b.name, 2, 40, 'your name');
  const password = cleanNewPassword(b.password);
  const { method, walletNumber } = await pickMethod(env, b.methodId, b.walletNumber);
  if (await accountByUid(env, uid)) throw new HttpError(409, 'You already have an account. Sign in with your ID and password.');
  const slot = await getDocMeta(env, `vipAccounts/${number}`);
  if (!slot || slot.data.unclaimed !== true || slot.data.googleUid) throw new HttpError(400, 'This account ID is not valid or was already used');
  const salt = rid();
  const r = await commit(env, [write(env, `vipAccounts/${number}`, {
    set: [[['name'], name], [['method'], method.name], [['methodId'], method.id], [['walletNumber'], walletNumber], [['googleUid'], uid], [['googleEmail'], email],
      [['pinSalt'], salt], [['pinHash'], await hashPin(salt, password)], [['pinFails'], 0], [['pinLockedUntil'], 0], [['recovery'], ''], [['unclaimed'], false]],
    ts: [['activatedAt']], updateTime: slot.updateTime,
  })]);
  if (r.ok) return json({ ok: true, number });
  if (isConflict(r)) throw new HttpError(409, 'This account ID was just used. Please check it.');
  mustCommit(r, 'Register');
});
