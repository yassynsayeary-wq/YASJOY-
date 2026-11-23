// GET /api/health — tells the admin panel whether the Cloudflare server is set up correctly (no secrets returned).
import { handler, json, serviceAccount, accessToken, getDoc } from '../_lib/fb.js';

export const onRequest = handler(async ({ env }) => {
  const out = { ok: true, functions: true, serviceAccount: false, firestore: false };
  try { serviceAccount(env); out.serviceAccount = true; }
  catch (e) { out.error = String((e && e.message) || e).slice(0, 200); return json(out); }
  try { await accessToken(env); await getDoc(env, 'settings/health'); out.firestore = true; }
  catch (e) { out.error = String((e && e.message) || e).slice(0, 200); }
  return json(out);
});
