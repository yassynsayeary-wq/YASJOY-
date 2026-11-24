// الحماية التلقائية على الخادم: تعمل حتى لو تطبيق المسؤول مغلق.
import { getDoc, queryEq, write, commit } from './fb.js';
import { scoreUser, normRules, ipsOf, banNoticeFor } from '../../guard-core.js';

const safe = async (p) => { try { return await p; } catch (e) { return []; } };
const toMs = (v) => (v ? Date.parse(v) || 0 : 0);

export async function runGuard(env, uid) {
  const [settings, userData] = await Promise.all([getDoc(env, 'adminSettings/fraud'), getDoc(env, `users/${uid}`)]);
  if (!userData) return { banned: false, skipped: true };
  const u = { ...userData, id: uid };
  if (u.banned === true) return { banned: true };
  const set = settings || {}, rules = normRules(set.rules), max = Math.max(3, Math.min(1000, Number(set.maxScore) || 10));
  if (set.autoBan !== true) return { banned: false, auto: false };
  if (u.fraudReviewedAt) return { banned: false, reviewed: true };

  const dev = u.device && typeof u.device === 'object' ? u.device : {};
  const q = [];
  if (dev.fp) q.push(safe(queryEq(env, 'users', 'device.fp', dev.fp, 50)));
  for (const ip of ipsOf(u).slice(0, 4)) for (const f of ['ip', 'ipv4', 'ipv6', 'previousIp']) q.push(safe(queryEq(env, 'users', f, ip, 20)));
  const [own, offers] = await Promise.all([safe(queryEq(env, 'withdrawals', 'uid', uid, 100)), safe(queryEq(env, 'transactions', 'uid', uid, 500))]);
  const wdsMap = new Map(own.map((x) => [x.id, { id: x.id, ...x.data }]));
  const wallets = [...new Set(own.map((x) => String(x.data.walletAddress || x.data.payoutAddress || x.data.binanceWallet || '').trim()).filter(Boolean))].slice(0, 4);
  for (const a of wallets) for (const f of ['walletAddress', 'payoutAddress', 'binanceWallet']) q.push(safe(queryEq(env, 'withdrawals', f, a, 20)));
  const res = await Promise.all(q), others = new Map();
  for (const list of res) for (const x of list) {
    if (x.path && x.path.startsWith('users/')) { if (x.id !== uid) others.set(x.id, { id: x.id, ...x.data }); }
    else wdsMap.set(x.id, { id: x.id, ...x.data });
  }
  const offerTimes = offers.filter((x) => x.data.type === 'offer').map((x) => toMs(x.data.createdAt)).filter(Boolean);
  const r = scoreUser(u, { others: [...others.values()], wds: [...wdsMap.values()], offerTimes, now: Date.now() }, rules);
  if (r.score < max) return { banned: false, score: r.score };

  const reasons = r.items.map((x) => x.t).join(' | ').slice(0, 500);
  const res2 = await commit(env, [write(env, `users/${uid}`, {
    set: [[['banned'], true], [['banReason'], 'fraud_auto'], [['bannedBy'], 'auto'], [['fraudScore'], r.score], [['fraudReasons'], reasons], [['banNotice'], banNoticeFor(r.items)]],
    ts: [['bannedAt']], exists: true,
  })]);
  return { banned: res2.ok, score: r.score };
}
