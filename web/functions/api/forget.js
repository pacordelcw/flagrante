/**
 * Erasure. GDPR Article 17, made real rather than promised.
 *
 * A privacy policy that says "write to us and we will delete it" is a promise
 * backed by someone remembering. This is a button that does it, and it is
 * deliberately unauthenticated: the visitor id is a random number that only the
 * browser holding it knows, so possessing it is the proof. Requiring an account
 * to delete data collected without an account would be absurd.
 *
 * The worst case for abuse is that someone who somehow guessed a 24-character
 * random id deletes an analytics row. That is a rounding error against making
 * erasure genuinely one click.
 *
 * Binding required: D1 database as `DB` (see schema.sql).
 */

const ID_PATTERN = /^[a-z0-9]{16,40}$/;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export async function onRequestPost({ request, env }) {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: "expected JSON" }, 400);
  }

  const id = String(payload?.id ?? "");
  if (!ID_PATTERN.test(id)) {
    return json({ error: "bad visitor id" }, 400);
  }

  try {
    // The visitor row, and the link from any waitlist entry back to this
    // browser. The waitlist entry itself stays -- it is keyed by an email
    // address the person typed in separately, and deleting that on the strength
    // of a browser id would let anyone unsubscribe anyone. That one goes
    // through the email address in the privacy page.
    const batch = await env.DB.batch([
      env.DB.prepare("DELETE FROM visitor WHERE id = ?1").bind(id),
      env.DB.prepare("UPDATE waitlist SET visitor_id = NULL WHERE visitor_id = ?1").bind(id),
    ]);

    const deleted = batch[0]?.meta?.changes ?? 0;
    return json({ ok: true, deleted });
  } catch (error) {
    // Never report success on a failed erasure. Someone acting on a right has
    // to be able to trust the answer.
    console.error("forget failed", error);
    return json({ error: "could not delete right now" }, 503);
  }
}

export async function onRequestGet() {
  return json({ error: "post a visitor id to delete it" }, 405);
}
