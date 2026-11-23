// POST /api/acct/me   (Authorization: Bearer <Google-signed-in Firebase ID token>)   body: {"number":"...","password":"..."} (both optional on the first call)
// states: register (no account for this Google user) | recover (admin reset it) | login (number + password needed) | ready (full data)
import { handler, json, HttpError, readJson, queryEq, verifyIdToken } from '../../_lib/fb.js';
import { accountByUid, checkPin, cleanPin, suspension, suspendedError, usd, byNewest, listMethods } from '../../_lib/vip.js';

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  const { uid, email } = await verifyIdToken(env, request);
  const found = await accountByUid(env, uid);
  if (!found) return json({ ok: true, state: 'register', email, methods: await listMethods(env) });
  const { number, acc } = found;
  const susp = suspension(acc);
  if (susp) throw suspendedError(susp);
  if (acc.recovery) return json({ ok: true, state: 'recover', email });
  const body = await readJson(request);
  if (!body.password) return json({ ok: true, state: 'login', email, name: acc.name || '' });
  await checkPin(env, number, acc, cleanPin(body.password), String(body.number || '').trim() === number);
  const [t, inv, methods] = await Promise.all([queryEq(env, 'vipTransfers', 'number', number), queryEq(env, 'vipInvoices', 'number', number), listMethods(env)]);
  const pts = Math.floor(Number(acc.points) || 0);
  return json({
    ok: true, state: 'ready', methods,
    account: { number, name: acc.name || '', method: acc.method || '', methodId: acc.methodId || (methods.find((m) => m.name === acc.method) || {}).id || '', walletNumber: acc.walletNumber || '', email: acc.googleEmail || email, points: pts, usd: usd(pts), accounts: Number(acc.accounts) || 0 },
    transfers: t.map((x) => x.data).sort(byNewest).slice(0, 100).map((x) => ({ points: x.points, usd: usd(x.points), from: x.publicId || '', createdAt: x.createdAt || '' })),
    invoices: inv.map((x) => x.data).sort(byNewest).slice(0, 100).map((x) => ({ invoiceNo: x.invoiceNo || '', points: x.points, usd: usd(x.points), reference: x.reference || '', method: x.method || '', walletNumber: x.walletNumber || '', createdAt: x.createdAt || '' })),
  });
});
