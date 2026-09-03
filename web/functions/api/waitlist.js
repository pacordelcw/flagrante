/**
 * Waitlist capture — Cloudflare Pages Function, D1 free tier.
 *
 * This endpoint is the measurement instrument for the whole experiment, so it
 * records the price that was on screen at the moment of signup. If the price
 * changes later, historical intent stays interpretable instead of becoming a
 * pile of undated email addresses.
 *
 * Binding required: D1 database as `DB` (see schema.sql).
 */

const MAX_EMAIL = 254;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

/** Deliberately permissive: rejecting a real address is worse than storing a junk one. */
function looksLikeEmail(value) {
  return (
    typeof value === "string" &&
    value.length > 3 &&
    value.length <= MAX_EMAIL &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
  );
}

export async function onRequestPost({ request, env }) {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: "expected JSON" }, 400);
  }

  const email = String(payload?.email ?? "").trim().toLowerCase();
  if (!looksLikeEmail(email)) {
    return json({ error: "that does not look like an email address" }, 400);
  }

  const priceShown = Number.isFinite(payload?.price_shown)
    ? Math.round(payload.price_shown)
    : null;
  const currency = String(payload?.currency ?? "EUR").slice(0, 3).toUpperCase();

  // Country and referrer tell us which channel produced the intent, which is
  // the thing we actually need to read off this experiment.
  const country = request.headers.get("CF-IPCountry") ?? null;
  const referer = (request.headers.get("Referer") ?? "").slice(0, 500) || null;

  try {
    await env.DB.prepare(
      `INSERT INTO waitlist (email, price_shown, currency, country, referer, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)
       ON CONFLICT(email) DO UPDATE SET
         price_shown = excluded.price_shown,
         seen_again_at = excluded.created_at`
    )
      .bind(email, priceShown, currency, country, referer, new Date().toISOString())
      .run();
  } catch (error) {
    // Never surface the database error to the caller, but do not pretend it
    // worked either -- a silent drop here corrupts the only metric that matters.
    console.error("waitlist insert failed", error);
    return json({ error: "could not record that right now" }, 503);
  }

  return json({ ok: true });
}

export async function onRequestGet() {
  return json({ error: "post an email to join the waitlist" }, 405);
}
