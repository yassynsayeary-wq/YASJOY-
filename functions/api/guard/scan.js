// POST /api/guard/scan  (Authorization: Bearer <ID token>) — يفحص المستخدم الحالي ويحظره تلقائيًا إن تجاوز الحد.
import { handler, json, HttpError, verifyIdToken } from '../../_lib/fb.js';
import { runGuard } from '../../_lib/guard.js';

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  const { uid } = await verifyIdToken(env, request);
  const r = await runGuard(env, uid);
  return json({ ok: true, banned: r.banned === true });
});
