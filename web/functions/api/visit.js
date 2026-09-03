/**
 * Return tracking — the measurement that decides the whole experiment.
 *
 * Gate 2 is a 30-day return rate: what share of people who ran a real scan
 * come back without being emailed. Returning unprompted *is* the paid product's
 * value proposition in miniature, which is why it predicts willingness to pay
 * better than anything we could ask.
 *
 * How it is measured: the browser generates a random id, keeps it in its own
 * localStorage, and sends it back on later visits. That is all. No cookie, no
 * account, no email, no IP stored, no fingerprinting, nothing that identifies a
 * person or survives a cleared browser.
 *
 * Which means the number is a LOWER BOUND: someone returning on a second
 * machine, in a private window, or after clearing storage counts as new. For a
 * go/no-go gate that is the right direction to be wrong in -- we would rather
 * kill a marginal business than continue one on inflated numbers.
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

  // "scan" means they actually put an SBOM through it -- a qualified
  // activation. A bare "visit" is someone who only looked at the page, and
  // counting those in the return rate would flatter the number.
  const scanned = payload?.event === "scan";
  const bucket = ["a", "b"].includes(payload?.price_bucket)
    ? payload.price_bucket
    : null;

  const now = new Date().toISOString();
  const country = request.headers.get("CF-IPCountry") ?? null;
  // Host only, never the full URL: a referring path can carry a query string
  // someone did not mean to share.
  let referer = null;
  try {
    const raw = request.headers.get("Referer");
    if (raw) referer = new URL(raw).host.slice(0, 120);
  } catch {
    referer = null;
  }

  try {
    await env.DB.prepare(
      `INSERT INTO visitor
         (id, first_seen, last_seen, visits, scans, price_bucket, first_referer, country)
       VALUES (?1, ?2, ?2, 1, ?3, ?4, ?5, ?6)
       ON CONFLICT(id) DO UPDATE SET
         last_seen = ?2,
         visits    = visitor.visits + 1,
         scans     = visitor.scans + ?3`
    )
      .bind(id, now, scanned ? 1 : 0, bucket, referer, country)
      .run();
  } catch (error) {
    console.error("visit upsert failed", error);
    return json({ error: "not recorded" }, 503);
  }

  return json({ ok: true });
}

export async function onRequestGet() {
  return json({ error: "post a visit" }, 405);
}
