// POST /api/admin/delete-user   body: {"uid":"<firebase uid>"}   (Authorization: Bearer <admin Firebase ID token>)
// Permanently deletes the user: Firestore user document, their withdrawals, their transactions AND the Firebase Auth login.
import { handler, json, HttpError, requireAdmin, readJson, isUid, queryEq, commit, del, mustCommit, deleteAuthUser, docName, DEFAULT_ADMIN_UID } from '../../_lib/fb.js';

export const onRequest = handler(async ({ request, env }) => {
  if (request.method !== 'POST') throw new HttpError(405, 'Use POST');
  await requireAdmin(env, request);
  const body = await readJson(request), uid = body && body.uid;
  if (!isUid(uid)) throw new HttpError(400, 'Invalid uid');
  if (uid === ((env && env.ADMIN_UID) || DEFAULT_ADMIN_UID)) throw new HttpError(400, 'The admin account cannot be deleted');

  const paths = new Set();
  for (const [col, field] of [['withdrawals', 'uid'], ['withdrawals', 'userId'], ['transactions', 'uid'], ['transactions', 'userId']]) {
    for (const d of await queryEq(env, col, field, uid)) paths.add(d.path);
  }
  const all = [...paths];
  for (let i = 0; i < all.length; i += 400) {
    mustCommit(await commit(env, all.slice(i, i + 400).map((p) => ({ delete: docName(env, p) }))), 'Deleting user records');
  }
  mustCommit(await commit(env, [del(env, `users/${uid}`)]), 'Deleting the user document');
  let authDeleted = true, authError = '';
  try { await deleteAuthUser(env, uid); } catch (e) { authDeleted = false; authError = e.message; }
  return json({ ok: true, deletedRecords: all.length, authDeleted, authError });
});
