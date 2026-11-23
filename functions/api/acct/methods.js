// GET /api/acct/methods   (public)   -> the categories the admin created (+ the built-in "Personal", which needs no ID)
import { handler, json, HttpError } from '../../_lib/fb.js';
import { listMethods } from '../../_lib/vip.js';

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'GET') throw new HttpError(405, 'Use GET');
  return json({ ok: true, methods: await listMethods(env) });
});
