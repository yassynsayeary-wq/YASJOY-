// POST /api/geo  (Authorization: Bearer <Firebase ID token of the signed-in user>)
// Records the user's IP + country from Cloudflare (server side, cannot be spoofed by the app).
// - The FIRST country seen is stored as the fixed country.
// - If the account later connects from a different country it is banned automatically.
import { handler, json, HttpError, verifyIdToken, getDoc, write, commit, mustCommit, clientGeo, isMissing } from '../_lib/fb.js';

const cut = (v, n) => String(v === undefined || v === null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const DEVICE_FIELDS = { ua: 300, platform: 60, platformVersion: 30, model: 60, brand: 60, lang: 20, langs: 100, tz: 60, screen: 24, dpr: 8, cores: 4, mem: 6, touch: 3, conn: 20, standalone: 5, vendor: 60, app: 20, fp: 40, gpu: 100, webdriver: 5 };

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  const { uid } = await verifyIdToken(env, request);
  let body = {};
  try { body = (await request.json()) || {}; } catch (e) { /* body is optional */ }
  const { ip, country } = clientGeo(request);
  const user = await getDoc(env, `users/${uid}`);
  if (!user) throw new HttpError(404, 'User document not found');
  if (!country && !ip) return json({ ok: true, skipped: true, banned: user.banned === true });

  const set = [], ts = [];
  let banned = user.banned === true, firstTime = false, rebased = false;

  if (country) {
    let name = '';
    try { name = new Intl.DisplayNames(['en'], { type: 'region' }).of(country) || ''; } catch (e) { /* optional */ }
    if (!user.countryCode) {
      // first detection => becomes the fixed country
      set.push([['countryCode'], country], [['lastCountryCode'], country], [['countrySrc'], 'cf']);
      if (name) set.push([['country'], name]);
      ts.push(['countryAt']);
      const k1 = String(Date.now());
      set.push([['geoLog', k1, 'type'], 'first'], [['geoLog', k1, 'to'], country], [['geoLog', k1, 'ip'], ip || '']);
      ts.push(['geoLog', k1, 'at']);
      firstTime = true;
    } else if (user.countrySrc !== 'cf') {
      // country was recorded earlier by the app (third-party lookup): re-baseline once, never ban on this step
      set.push([['countryCode'], country], [['lastCountryCode'], country], [['countrySrc'], 'cf']);
      if (name) set.push([['country'], name]);
      ts.push(['countryAt']);
      rebased = true;
    } else if (user.countryCode !== country && user.banned !== true) {
      set.push([['banned'], true], [['banReason'], 'country_change'], [['bannedBy'], 'auto'],
        [['lastCountryCode'], country], [['previousCountryCode'], user.countryCode]);
      if (name) set.push([['lastCountry'], name]);
      ts.push(['bannedAt']);
      const k2 = String(Date.now());
      set.push([['geoLog', k2, 'type'], 'change'], [['geoLog', k2, 'from'], user.countryCode], [['geoLog', k2, 'to'], country], [['geoLog', k2, 'ip'], ip || '']);
      ts.push(['geoLog', k2, 'at']);
      banned = true;
    } else if (user.lastCountryCode && user.lastCountryCode !== country) {
      // already banned / returning: keep a record of every country the account is seen from
      const k3 = String(Date.now());
      set.push([['lastCountryCode'], country], [['geoLog', k3, 'type'], country === user.countryCode ? 'return' : 'change'], [['geoLog', k3, 'from'], user.lastCountryCode], [['geoLog', k3, 'to'], country], [['geoLog', k3, 'ip'], ip || '']);
      ts.push(['geoLog', k3, 'at']);
    }
  }
  if (ip && user.ip !== ip) {
    if (user.ip) set.push([['previousIp'], user.ip]);
    set.push([['ip'], ip]);
    ts.push(['ipAt']);
  }
  if (ip) {
    const fam = ip.includes(':') ? 'ipv6' : 'ipv4';
    if (user[fam] !== ip) set.push([[fam], ip]);
  }
  const cf = request.cf || {};
  const net = { asn: cf.asn, org: cf.asOrganization, city: cf.city, region: cf.region, tz: cf.timezone, continent: cf.continent, colo: cf.colo, country: cf.country };
  const famKey = ip.includes(':') ? 'net6' : 'net4';
  for (const key of ['net', ip ? famKey : null]) {
    if (!key) continue;
    const oldNet = user[key] && typeof user[key] === 'object' ? user[key] : {};
    for (const [k, v] of Object.entries(net)) { const c = cut(v, 80); if (c && String(oldNet[k] ?? '') !== c) set.push([[key, k], c]); }
  }
  const dev = body && typeof body.device === 'object' && body.device ? body.device : {};
  const oldDev = user.device && typeof user.device === 'object' ? user.device : {};
  let devChanged = false;
  for (const [k, max] of Object.entries(DEVICE_FIELDS)) { const c = cut(dev[k], max); if (c && String(oldDev[k] ?? '') !== c) { set.push([['device', k], c]); devChanged = true; } }
  if (devChanged) ts.push(['deviceAt']);
  if (set.length || ts.length) {
    const r = await commit(env, [write(env, `users/${uid}`, { set, ts, exists: true })]);
    if (!r.ok && isMissing(r)) throw new HttpError(404, 'User document not found');
    mustCommit(r, 'Saving geo data');
  }
  return json({ ok: true, countryCode: user.countryCode || country || '', ip, banned, firstTime, rebased });
});
