// POST /api/acct/transfer   body: {"number":"<third-app private number>"}   (Authorization: Bearer <user Firebase ID token>)
// Moves the user's coins that were EARNED FROM OFFER WALLS to the linked account (coins added any other way stay in the balance). Atomic, server-side, cannot be forged by the client.
import { handler, json, HttpError, verifyIdToken, readJson, getDoc, getDocMeta, queryEq, commit, write, mustCommit } from '../../_lib/fb.js';
import { cleanNumber, suspension, suspendedError, usd, rid, vipSettings, isConflict } from '../../_lib/vip.js';

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  const { uid } = await verifyIdToken(env, request);
  const body = await readJson(request), number = cleanNumber(body.number);
  for (let attempt = 0; attempt < 4; attempt++) {
    const user = await getDocMeta(env, `users/${uid}`);
    if (!user) throw new HttpError(404, 'User not found');
    if (user.data.banned === true) throw new HttpError(403, 'This account is banned');
    if (!(await vipSettings(env)).enabled) throw new HttpError(403, 'This option is currently unavailable');
    const acc = await getDoc(env, `vipAccounts/${number}`);
    if (!acc || acc.unclaimed === true || !acc.googleUid) throw new HttpError(404, 'Account ID not found');
    const susp = suspension(acc); if (susp) throw suspendedError(susp);
    const bal = Math.floor(Number(user.data.balance) || 0);
    if (bal <= 0) throw new HttpError(400, 'You have no coins to transfer');
    const earned = Math.floor(Number(user.data.offerPoints) || 0), sent = Math.floor(Number(user.data.acctSent) || 0);
    const wds = await queryEq(env, 'withdrawals', 'uid', uid, 300);
    const withdrawn = wds.reduce((t, x) => t + (x.data.status === 'rejected' ? 0 : Math.floor(Number(x.data.coins) || 0)), 0);
    const amount = Math.min(bal, Math.max(0, earned - withdrawn - sent));
    if (amount <= 0) throw new HttpError(400, 'No coins earned from offer walls are available to send');
    const member = await getDoc(env, `vipAccounts/${number}/members/${uid}`);
    const id = rid(), pid = user.data.publicId || '';
    const r = await commit(env, [
      write(env, `users/${uid}`, { set: [[['balance'], bal - amount], [['lastAcctTransferId'], id]], inc: [[['acctSent'], amount]], updateTime: user.updateTime }),
      write(env, `vipAccounts/${number}`, { inc: [[['points'], amount], ...(member ? [] : [[['accounts'], 1]])], ts: [['updatedAt']], exists: true }),
      write(env, `vipAccounts/${number}/members/${uid}`, { set: [[['uid'], uid], [['publicId'], pid]], inc: [[['total'], amount]], ts: [['lastAt']] }),
      write(env, `vipTransfers/${id}`, { set: [[['number'], number], [['uid'], uid], [['publicId'], pid], [['points'], amount]], ts: [['createdAt']], exists: false }),
      write(env, `transactions/${id}`, { set: [[['uid'], uid], [['type'], 'acct_transfer'], [['coins'], -amount], [['number'], number]], ts: [['createdAt']], exists: false }),
    ]);
    if (r.ok) return json({ ok: true, transferred: amount, held: bal - amount, usd: usd(amount) });
    if (!isConflict(r)) mustCommit(r, 'Transfer');
  }
  throw new HttpError(409, 'Your balance changed during the transfer. Please try again.');
});
