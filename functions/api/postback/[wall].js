// GET|POST /api/postback/<wallId>?uid=<firebase uid>&amount=<reward>&txid=<provider transaction id>&sig=<signature>
// Called by the offer-wall provider (server to server). Credits the user's balance after verifying the signature.
//
// Per wall (Firestore):  offerWalls/<id>        { name, provider, rate (points per 1 unit of provider reward), verify: 'key'|'md5'|'sha256'|'hmac' }
//                        offerWallSecrets/<id>  { secret }
// verify modes (sig sent by the provider):
//   key    : sig === secret                       (put &sig=YOUR_SECRET as a fixed value in the postback URL)
//   md5    : sig === md5(txid + '-' + secret)
//   sha256 : sig === sha256(txid + '-' + secret)
//   hmac   : sig === HMAC_SHA256(secret, uid + '|' + amount + '|' + txid)
//   lootably: sig === sha256(userID + ip + revenue + currencyReward + secret)   (send &ip= &revenue= too)
//   bitlabs : sig === HMAC_SHA1(secret, full URL without the trailing &hash=...)   (BitLabs appends &hash= itself)
//   tapjoy : sig === md5(id:snuid:currency:secret)   (Tapjoy currency callback: appends snuid, currency, id, verifier itself)
// Parameter names are flexible: uid|snuid|user_id..., amount|currency|reward|points..., txid|id|trans_id|transaction_id..., sig|verifier|hash|signature...
import { handler, text, HttpError, getDoc, write, commit, isAlreadyExists, isMissing, mustCommit,
  md5Hex, sha256Hex, hmacSha256Hex, hmacSha1Hex, timingSafeEqual, isUid } from '../../_lib/fb.js';
import { runGuard } from '../../_lib/guard.js';

const clean = (s) => String(s || '').trim();
const MAX_POINTS = 5_000_000;

async function params(request) {
  const url = new URL(request.url), p = Object.fromEntries(url.searchParams);
  if (request.method === 'POST') {
    const ct = request.headers.get('content-type') || '';
    try {
      if (ct.includes('application/json')) Object.assign(p, await request.json());
      else if (ct.includes('application/x-www-form-urlencoded')) Object.assign(p, Object.fromEntries(new URLSearchParams(await request.text())));
    } catch (e) { /* ignore body errors */ }
  }
  return p;
}
async function log(env, wallId, result, p, request) {
  try {
    const id = crypto.randomUUID();
    await commit(env, [write(env, `postbackLogs/${id}`, {
      set: [[['wallId'], wallId], [['result'], result], [['uid'], clean(p.uid).slice(0, 40)], [['txid'], clean(p.txid).slice(0, 80)],
        [['amount'], clean(p.amount).slice(0, 20)], [['ip'], clean(request.headers.get('cf-connecting-ip')).slice(0, 45)]],
      ts: [['createdAt']], exists: false,
    })]);
  } catch (e) { console.error('postback log failed', e); }
}

export const onRequest = handler(async ({ request, env, params: routeParams, waitUntil }) => {
  if (request.method !== 'GET' && request.method !== 'POST') throw new HttpError(405, 'Use GET or POST');
  const wallId = clean(routeParams && routeParams.wall);
  if (!isUid(wallId)) return text('ERROR: bad wall', 400);
  const p = await params(request);
  const pick = (names) => { for (const n of names) if (p[n] !== undefined && clean(p[n]) !== '') return clean(p[n]); return ''; };
  const uid = pick(['uid', 'snuid', 'user_id', 'userid', 'userId', 'sub_id', 'subid', 'player_id', 'userID', 'external_identifier', 'externalIdentifier']),
    txid = pick(['txid', 'id', 'trans_id', 'transaction_id', 'transactionId', 'txn_id', 'tid', 'oid', 'tx', 'transactionID']),
    sig = pick(['sig', 'verifier', 'hash', 'signature', 'secure_hash', 'mac']),
    amountRaw = pick(['amount', 'currency', 'reward', 'points', 'virtual_currency', 'amount_local', 'value', 'val', 'currencyReward', 'currency_amount']);
  const ipP = pick(['ip', 'user_ip']), revenue = pick(['revenue', 'payout', 'payout_usd']), status = pick(['status']);
  const logP = { uid, txid, amount: amountRaw };

  const wall = await getDoc(env, `offerWalls/${wallId}`);
  if (!wall) return text('ERROR: unknown wall', 404);
  const sec = await getDoc(env, `offerWallSecrets/${wallId}`);
  const secret = sec && typeof sec.secret === 'string' ? sec.secret : '';
  if (!secret) return text('ERROR: wall is not configured', 503);

  // ---- verify signature ----
  const mode = clean(wall.verify) || 'key';
  let expected = '';
  if (mode === 'key') expected = secret;
  else if (mode === 'md5') expected = md5Hex(txid + '-' + secret);
  else if (mode === 'sha256') expected = await sha256Hex(txid + '-' + secret);
  else if (mode === 'hmac') expected = await hmacSha256Hex(secret, uid + '|' + amountRaw + '|' + txid);
  else if (mode === 'lootably') expected = await sha256Hex(uid + ipP + revenue + amountRaw + secret);
  else if (mode === 'bitlabs') {
    const u = request.url, i = u.lastIndexOf('&hash=');
    expected = i < 0 ? '' : await hmacSha1Hex(secret, u.slice(0, i));
  }
  else if (mode === 'tapjoy') expected = md5Hex(txid + ':' + uid + ':' + amountRaw + ':' + secret);
  else return text('ERROR: wall verify mode is invalid', 503);
  const ok = sig && expected && (mode === 'key' ? timingSafeEqual(sig, expected) : timingSafeEqual(sig.toLowerCase(), expected.toLowerCase()));
  if (!ok) { await log(env, wallId, 'bad_signature', logP, request); return text('ERROR: invalid signature', 403); }

  // chargebacks / reversals (Lootably status=0, AyeT transaction ids prefixed r-) are never credited
  if (status === '0' || /^r-/i.test(txid)) return text('OK ignored');
  // ---- validate ----
  if (!isUid(uid) || !txid || txid.length > 200) { await log(env, wallId, 'bad_request', logP, request); return text('ERROR: bad request', 400); }
  const amount = Number(amountRaw);
  if (!Number.isFinite(amount)) { await log(env, wallId, 'bad_amount', logP, request); return text('ERROR: bad amount', 400); }
  const rate = Number(wall.rate) > 0 ? Number(wall.rate) : 1;
  const coins = Math.round(amount * rate);
  if (coins <= 0) return text('OK ignored');             // reversals / zero rewards are not credited
  if (!Number.isSafeInteger(coins) || coins > MAX_POINTS) { await log(env, wallId, 'amount_too_large', logP, request); return text('ERROR: amount too large', 400); }

  // ---- credit once (transaction id is the idempotency key) ----
  const txDoc = `offer_${wallId}_${txid.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 150)}`;
  const r = await commit(env, [
    write(env, `transactions/${txDoc}`, {
      set: [[['uid'], uid], [['type'], 'offer'], [['coins'], coins], [['wallId'], wallId], [['wallName'], clean(wall.name)],
        [['provider'], clean(wall.provider)], [['txid'], txid], [['amount'], amount], [['rate'], rate]],
      ts: [['createdAt']], exists: false,
    }),
    write(env, `users/${uid}`, { inc: [[['balance'], coins], [['offerPoints'], coins], [['offerCount'], 1], [['wallPoints', wallId], coins]], ts: [['lastOfferAt']], exists: true }),
  ]);
  if (r.ok) {
    // فحص الحماية التلقائية بعد كل مكافأة (حتى لو المسؤول غير متصل)
    const g = runGuard(env, uid).catch(() => null);
    if (typeof waitUntil === 'function') waitUntil(g); else await g;
    return text('OK');
  }
  if (isAlreadyExists(r)) return text('OK duplicate');
  if (isMissing(r)) { await log(env, wallId, 'user_not_found', logP, request); return text('ERROR: user not found', 404); }
  mustCommit(r, 'Crediting points');
  return text('OK');
});
