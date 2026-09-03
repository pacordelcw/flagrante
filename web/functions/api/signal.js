/**
 * Anonymous post-scan signal — this is S3 running as a by-product of S4.
 *
 * The point of this endpoint is to learn who actually shows up and what they
 * are doing about Article 14, without interviewing anyone. What it stores is
 * deliberately thin: two optional free-text-ish answers and the *counts* from
 * a scan. No email, no component names, no SBOM. The scanner never sends the
 * component list here and could not, because it never keeps one.
 *
 * Binding required: D1 database as `DB` (see schema.sql).
 */

const MAX_MAKES = 120;

const DOING_OPTIONS = new Set([
  "Nothing yet",
  "Working out whether it applies to us",
  "A manual process someone owns",
  "Automated in our pipeline",
  "An external consultant handles it",
]);

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function wholeNumber(value) {
  return Number.isFinite(value) && value >= 0 ? Math.round(value) : null;
}

export async function onRequestPost({ request, env }) {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: "expected JSON" }, 400);
  }

  const makes = String(payload?.makes ?? "").trim().slice(0, MAX_MAKES) || null;
  const doingRaw = String(payload?.doing ?? "").trim();
  // Only accept the options we offered. Free text in this field would be an
  // invitation to paste something identifying, which defeats the purpose.
  const doing = DOING_OPTIONS.has(doingRaw) ? doingRaw : null;

  if (!makes && !doing) {
    return json({ error: "nothing to record" }, 400);
  }

  const counts = payload?.counts ?? {};
  const country = request.headers.get("CF-IPCountry") ?? null;

  try {
    await env.DB.prepare(
      `INSERT INTO signal
         (makes, doing, components_checked, sbom_format,
          clock_running, urgent_review, monitor, unresolvable,
          country, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`
    )
      .bind(
        makes,
        doing,
        wholeNumber(payload?.components_checked),
        String(payload?.sbom_format ?? "").slice(0, 20) || null,
        wholeNumber(counts.clock_running),
        wholeNumber(counts.urgent_review),
        wholeNumber(counts.monitor),
        wholeNumber(counts.unresolvable),
        country,
        new Date().toISOString()
      )
      .run();
  } catch (error) {
    console.error("signal insert failed", error);
    return json({ error: "could not record that right now" }, 503);
  }

  return json({ ok: true });
}

export async function onRequestGet() {
  return json({ error: "post a signal" }, 405);
}
