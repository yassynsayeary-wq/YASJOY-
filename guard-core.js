// guard-core.js — الحماية التلقائية (مصدر واحد للقواعد والحساب)
// يُستخدم في: تطبيق المسؤول (عرض مباشر) + الخادم functions/_lib/guard.js (حظر تلقائي حتى لو المسؤول غير موجود).
// دوال نقية بلا أي اتصال بالشبكة.

export const HOST_RE = /(ovh|amazon|aws|google (cloud|llc)|digitalocean|hetzner|m247|vultr|linode|choopa|leaseweb|contabo|microsoft|azure|oracle|datacamp|nordvpn|expressvpn|proton|mullvad|surfshark|cyberghost|packethub|quadranet|zenlayer|vpn|hosting|datacenter|data center|colo|server|cloud)/i;
export const EMU_RE = /(sdk_gphone|emulator|generic_x86|android sdk built|genymotion|google_sdk|bluestacks|nox|ldplayer)/i;
export const TZC = {'Asia/Aden':'YE','Asia/Riyadh':'SA','Asia/Dubai':'AE','Asia/Qatar':'QA','Asia/Kuwait':'KW','Asia/Bahrain':'BH','Asia/Muscat':'OM','Asia/Baghdad':'IQ','Asia/Damascus':'SY','Asia/Beirut':'LB','Asia/Amman':'JO','Asia/Jerusalem':'IL','Africa/Cairo':'EG','Africa/Khartoum':'SD','Africa/Tripoli':'LY','Africa/Tunis':'TN','Africa/Algiers':'DZ','Africa/Casablanca':'MA','Africa/Mogadishu':'SO','Africa/Djibouti':'DJ','Europe/London':'GB','Europe/Paris':'FR','Europe/Berlin':'DE','Europe/Madrid':'ES','Europe/Rome':'IT','Europe/Amsterdam':'NL','Europe/Istanbul':'TR','Europe/Moscow':'RU','Asia/Istanbul':'TR','Asia/Tehran':'IR','Asia/Karachi':'PK','Asia/Kolkata':'IN','Asia/Calcutta':'IN','Asia/Dhaka':'BD','Asia/Jakarta':'ID','Asia/Manila':'PH','Asia/Singapore':'SG','Asia/Tokyo':'JP','Asia/Seoul':'KR','Asia/Shanghai':'CN','Asia/Hong_Kong':'HK','Africa/Lagos':'NG','Africa/Nairobi':'KE','Africa/Johannesburg':'ZA','America/New_York':'US','America/Chicago':'US','America/Denver':'US','America/Los_Angeles':'US','America/Toronto':'CA','America/Sao_Paulo':'BR','America/Mexico_City':'MX','Australia/Sydney':'AU'};

/** أنواع القواعد: label عربي للمسؤول، en للمستخدم عند الحظر، params الحقول القابلة للتعديل. */
export const RULE_KINDS = {
  vpn:      { label: 'VPN مرجّح', en: 'Using a VPN / proxy to hide your location', params: [] },
  proxy:    { label: 'احتمال VPN أو بروكسي عادي', en: 'Suspicious network connection', params: [] },
  device:   { label: 'نفس الجهاز على أكثر من N حسابات', en: 'Several accounts on the same device', params: [['n', 'عدد الحسابات الأخرى', 3]] },
  ip:       { label: 'نفس عنوان IP على أكثر من N حسابات', en: 'Several accounts on the same network address', params: [['n', 'عدد الحسابات الأخرى', 3]] },
  emulator: { label: 'محاكي أو أداة آلية (اختراق)', en: 'Emulator or automation tool detected', params: [] },
  speed:    { label: 'سرعة عروض غير طبيعية (معدل/ساعة)', en: 'Unnatural offer completion speed', params: [['n', 'عروض في الساعة', 10]] },
  burst:    { label: 'عروض كثيرة في وقت قصير', en: 'Too many offers completed in a very short time', params: [['n', 'عدد العروض', 10], ['minutes', 'خلال (دقيقة)', 30]] },
  country:  { label: 'تغيّر الدولة', en: 'Your country changed', params: [['n', 'عدد التغيّرات', 2]] },
  wallet:   { label: 'نفس محفظة السحب بحسابات متعددة', en: 'The same payout wallet is used on several accounts', params: [] },
  unbacked: { label: 'رصيد غير مدعوم بنقاط الجدران', en: 'Balance that was not earned through offer walls', params: [] },
  newWd:    { label: 'سحب من حساب جديد جدًا', en: 'Withdrawal requested from a brand-new account', params: [['hours', 'عمر الحساب (ساعة)', 24]] },
  banEvade: { label: 'مرتبط بحساب محظور (نفس الجهاز أو IP)', en: 'Linked to an account that was already banned', params: [] },
  wdBurst:  { label: 'طلبات سحب كثيرة خلال 24 ساعة', en: 'Too many withdrawal requests in one day', params: [['n', 'عدد الطلبات', 3]] },
};

let _id = 0;
const R = (kind, points, extra) => ({ id: 'd_' + kind + (_id++), kind, points, enabled: true, ...extra });
export const defaultRules = () => { _id = 0; return [
  R('vpn', 10), R('proxy', 1), R('device', 10, { n: 3 }), R('emulator', 10), R('speed', 5, { n: 10 }),
  R('burst', 30, { n: 10, minutes: 30 }), R('wallet', 4), R('ip', 2, { n: 3 }), R('country', 2, { n: 2 }),
  R('unbacked', 4), R('newWd', 4, { hours: 24 }), R('wdBurst', 3, { n: 3 }), R('banEvade', 6),
]; };

/** يقرأ القواعد المحفوظة (أو الافتراضية) ويُنظّفها */
export function normRules(raw) {
  if (!Array.isArray(raw) || !raw.length) return defaultRules();
  return raw.filter((r) => r && RULE_KINDS[r.kind]).map((r, i) => {
    const k = RULE_KINDS[r.kind], o = { id: String(r.id || ('r' + i)), kind: r.kind, enabled: r.enabled !== false, points: Math.max(0, Math.min(1000, Number(r.points) || 0)) };
    k.params.forEach(([p, , d]) => { o[p] = Number(r[p]) > 0 ? Number(r[p]) : d; });
    return o;
  });
}

export function vpnCheck(u) {
  const dev = u.device && typeof u.device === 'object' ? u.device : {}, net = u.net || {}, n4 = u.net4 || {}, n6 = u.net6 || {};
  const ipCountries = [...new Set([n4.country, n6.country, net.country, u.countryCode].filter(Boolean))];
  const orgs = [net.org, n4.org, n6.org].filter(Boolean), host = orgs.find((o) => HOST_RE.test(o));
  const tzCountry = TZC[dev.tz] || '', langCountry = ((String(dev.lang || '').match(/[-_]([A-Za-z]{2})$/) || [])[1] || '').toUpperCase();
  const devCountry = tzCountry || langCountry, reasons = [];
  if (host) reasons.push('شبكة استضافة/مراكز بيانات: ' + host);
  if (n4.country && n6.country && n4.country !== n6.country) reasons.push('دولة IPv4 (' + n4.country + ') تختلف عن دولة IPv6 (' + n6.country + ')');
  const tzs = [n4.tz, n6.tz, net.tz].filter(Boolean);
  if (dev.tz && tzs.length && !tzs.includes(dev.tz)) reasons.push('منطقة الجهاز الزمنية (' + dev.tz + ') لا تطابق منطقة الـIP (' + tzs[0] + ')');
  const mismatch = devCountry && ipCountries.length && !ipCountries.includes(devCountry) ? { dev: devCountry, ip: ipCountries.join('، ') } : null;
  if (mismatch) reasons.push('دولة الجهاز (' + mismatch.dev + ') تختلف عن دولة الـIP (' + mismatch.ip + ')');
  const state = !u.net && !u.net4 && !u.net6 ? 'unknown' : reasons.length >= 2 || host ? 'yes' : reasons.length ? 'maybe' : 'no';
  return { state, reasons, host, devCountry, mismatch, ipCountries };
}

const toMs = (v) => (v && v.toMillis ? v.toMillis() : v && v.seconds ? v.seconds * 1000 : v ? Date.parse(v) || 0 : 0);
const wdUid = (w) => String(w.uid || w.userId || '').trim();
const wdWallet = (w) => String(w.walletAddress || w.payoutAddress || w.binanceWallet || '').trim();
const wdCoins = (w) => Math.abs(Math.floor(Number(w.coins ?? w.points ?? w.amountCoins) || 0));
export const ipsOf = (u) => [u.ip, u.ipv4, u.ipv6, u.previousIp].filter(Boolean);

/** رصيد غير مدعوم بنقاط الجدران */
export function unbackedOf(u, wds) {
  const bal = Math.floor(Number(u.balance) || 0); if (bal <= 0) return 0;
  const wd = (wds || []).filter((w) => wdUid(w) === String(u.id) && w.status !== 'rejected').reduce((t, w) => t + wdCoins(w), 0);
  const backed = Math.max(0, Math.floor(Number(u.offerPoints) || 0) - wd - Math.floor(Number(u.acctSent) || 0));
  return Math.max(0, bal - backed);
}

/**
 * ctx: { others:[user docs with id], wds:[withdrawals], offerTimes:[ms] (عروض هذا المستخدم), now:ms }
 * ينتج {score, items:[{id,kind,p,t,en,d}]}
 */
export function scoreUser(u, ctx, rules) {
  const items = []; let score = 0; const now = ctx.now || Date.now();
  const dev = u.device && typeof u.device === 'object' ? u.device : {};
  const others = (ctx.others || []).filter((x) => x.id !== u.id), wds = ctx.wds || [], nm = (x) => x.publicId || String(x.id).slice(0, 8);
  const add = (r, t, d) => { score += r.points; items.push({ id: r.id, kind: r.kind, p: r.points, t, en: RULE_KINDS[r.kind].en, d: d || '' }); };
  const vc = vpnCheck(u);
  const wallets = new Set(wds.filter((w) => wdUid(w) === String(u.id)).map(wdWallet).filter(Boolean));
  const myWd = wds.filter((w) => wdUid(w) === String(u.id));
  const created = toMs(u.createdAt), hrs = created ? Math.max(1, (now - created) / 36e5) : 0, oc = Number(u.offerCount) || 0;
  for (const r of rules) {
    if (!r.enabled || !(r.points > 0)) continue;
    switch (r.kind) {
      case 'vpn': if (vc.state === 'yes') add(r, 'يستخدم VPN (مرجّح)', vc.reasons.join(' · ')); break;
      case 'proxy': if (vc.state === 'maybe') add(r, 'احتمال VPN / بروكسي عادي', vc.reasons.join(' · ')); break;
      case 'device': {
        const s = dev.fp ? others.filter((x) => x.device && x.device.fp === dev.fp) : [];
        if (s.length >= r.n) add(r, 'نفس الجهاز على ' + (s.length + 1) + ' حسابات (الحد ' + r.n + ')', s.slice(0, 6).map(nm).join('، ')); break;
      }
      case 'ip': {
        const ips = ipsOf(u), s = ips.length ? others.filter((x) => ipsOf(x).some((v) => ips.includes(v))) : [];
        if (s.length >= r.n) add(r, 'نفس عنوان IP على ' + (s.length + 1) + ' حسابات', s.slice(0, 6).map(nm).join('، ')); break;
      }
      case 'emulator':
        if (EMU_RE.test((dev.ua || '') + ' ' + (dev.model || '')) || String(dev.webdriver) === 'true' || /(swiftshader|llvmpipe|virtualbox|vmware|android emulator)/i.test(dev.gpu || '')) add(r, 'محاكي أو أداة آلية (اختراق محتمل)', dev.gpu || dev.model || ''); break;
      case 'speed': if (oc >= 10 && hrs && oc / hrs > r.n) add(r, 'سرعة إتمام عروض غير طبيعية', oc + ' عرضًا خلال ' + Math.round(hrs) + ' ساعة'); break;
      case 'burst': {
        const t = (ctx.offerTimes || []).slice().sort((a, b) => a - b), w = r.minutes * 60000; let best = 0, j = 0;
        for (let i = 0; i < t.length; i++) { while (t[i] - t[j] > w) j++; best = Math.max(best, i - j + 1); }
        if (best >= r.n) add(r, best + ' عرضًا خلال ' + r.minutes + ' دقيقة (الحد ' + r.n + ')', ''); break;
      }
      case 'country': {
        const n = u.geoLog && typeof u.geoLog === 'object' ? Object.values(u.geoLog).filter((e) => e && e.type !== 'first').length : 0;
        if (n >= r.n) add(r, 'تغيّر الدولة ' + n + ' مرات', ''); break;
      }
      case 'wallet': {
        if (!wallets.size) break; const shared = new Set();
        wds.forEach((w) => { const a = wdWallet(w); if (a && wallets.has(a) && wdUid(w) !== String(u.id)) shared.add(wdUid(w)); });
        if (shared.size) add(r, 'نفس محفظة السحب مستخدمة في ' + (shared.size + 1) + ' حسابات', ''); break;
      }
      case 'banEvade': {
        const ips = ipsOf(u), s = others.filter((x) => x.banned === true && ((dev.fp && x.device && x.device.fp === dev.fp) || (ips.length && ipsOf(x).some((v) => ips.includes(v)))));
        if (s.length) add(r, 'مرتبط بحساب محظور (نفس الجهاز/IP)', s.slice(0, 6).map(nm).join('، ')); break;
      }
      case 'unbacked': { const b = unbackedOf(u, wds); if (b > 0) add(r, 'رصيد غير مدعوم بنقاط الجدران: ' + b.toLocaleString('en-US') + ' نقطة', 'أُضيف بغير جدار — لن يُحوَّل إلى حساب مميز'); break; }
      case 'newWd': if (myWd.length && created && now - created < r.hours * 36e5) add(r, 'طلب سحب من حساب عمره أقل من ' + r.hours + ' ساعة', ''); break;
      case 'wdBurst': {
        const c = myWd.filter((w) => now - toMs(w.createdAt) < 864e5).length;
        if (c >= r.n) add(r, c + ' طلبات سحب خلال 24 ساعة (الحد ' + r.n + ')', ''); break;
      }
    }
  }
  return { score, items };
}

/** رسالة تُعرض للمستخدم بعد الحظر التلقائي */
export const banNoticeFor = (items) => [...new Set(items.map((x) => x.en))].join(' | ').slice(0, 400);
