// POST /api/acct/register   (Authorization: Bearer <Google-signed-in Firebase ID token>)
// body: {"number":"<account ID issued by the admin>","pin":"<6-digit PIN issued with it>","name":"Ali","methodId":"personal|none|<category id>","walletNumber":"(not needed for Personal/None)"}
// Activates an account ID that the admin created in advance. Without a valid unused ID + its PIN nothing can be created.
import { handler, json, HttpError, readJson, getDocMeta, commit, write, mustCommit, verifyIdToken, timingSafeEqual } from '../../_lib/fb.js';
import { accountByUid, cleanNumber, cleanPin6, cleanText, pickMethod, isConflict } from '../../_lib/vip.js';

const MAX_FAILS = 5, LOCK_MS = 15 * 60 * 1000;

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  const { uid, email } = await verifyIdToken(env, request);
  if (!email) throw new HttpError(401, 'Please sign in with Google');
  const b = await readJson(request);
  const number = cleanNumber(b.number);
  const pin = cleanPin6(b.pin);
  const name = cleanText(b.name, 2, 40, 'your name');
  const { method, walletNumber } = await pickMethod(env, b.methodId, b.walletNumber);
  if (await accountByUid(env, uid)) throw new HttpError(409, 'You already have an account on this Google account.');
  const slot = await getDocMeta(env, `vipAccounts/${number}`);
  if (!slot || slot.data.unclaimed !== true || slot.data.googleUid) throw new HttpError(400, 'This account ID is not valid or was already used');
  const now = Date.now();
  if (Number(slot.data.pinLockedUntil) > now) throw new HttpError(429, `Too many wrong attempts. Try again in ${Math.ceil((slot.data.pinLockedUntil - now) / 60000)} min`);
  if (!slot.data.pin) throw new HttpError(400, 'This account ID has no PIN yet. Ask the admin to issue a PIN.');
  if (!timingSafeEqual(String(slot.data.pin), pin)) {
    const fails = (Number(slot.data.pinFails) || 0) + 1;
    await commit(env, [write(env, `vipAccounts/${number}`, { set: [[['pinFails'], fails >= MAX_FAILS ? 0 : fails], [['pinLockedUntil'], fails >= MAX_FAILS ? now + LOCK_MS : 0]], exists: true })]);
    throw new HttpError(401, fails >= MAX_FAILS ? 'Too many wrong attempts. Locked for 15 minutes' : 'Wrong PIN for this Account ID');
  }
  const r = await commit(env, [write(env, `vipAccounts/${number}`, {
    set: [[['name'], name], [['method'], method.name], [['methodId'], method.id], [['walletNumber'], walletNumber], [['googleUid'], uid], [['googleEmail'], email],
      [['pinFails'], 0], [['pinLockedUntil'], 0], [['unclaimed'], false]],
    ts: [['activatedAt']], updateTime: slot.updateTime,
  })]);
  if (r.ok) return json({ ok: true, number });
  if (isConflict(r)) throw new HttpError(409, 'This account ID was just used. Please check it.');
  mustCommit(r, 'Register');
});
77
