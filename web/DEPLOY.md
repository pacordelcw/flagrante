# Deploying flagrante.dev

Total running cost: **the domain only.** Everything else sits inside free tiers
that permit commercial use, which is why this stack was chosen over Vercel —
Vercel's Hobby tier forbids commercial use, so the first euro of revenue would
force a migration or a $20/month upgrade. Nothing here should push a decision
before the experiment has answered its own question.

| Layer | Service | Cost |
|---|---|---|
| Domain + DNS | Cloudflare Registrar | ~$12/year, sold at cost |
| Landing + result pages | Cloudflare Pages | free, unlimited static requests |
| Waitlist API | Pages Functions | free, 100k requests/day |
| Waitlist storage | Cloudflare D1 | free, 5 GB |
| Scan API (later) | Google Cloud Run | free to 2M requests/month, scales to zero |

Cloud Run needs a GCP account with billing enabled even to use the free tier.

## First deploy

```bash
npm install -g wrangler
wrangler login

# 1. Create the database and paste the returned id into wrangler.toml
wrangler d1 create flagrante

# 2. Apply the schema
wrangler d1 execute flagrante --remote --file=schema.sql

# 3. Ship
wrangler pages deploy . --project-name=flagrante
```

Then in the Cloudflare dashboard, bind the D1 database to the Pages project as
`DB` (Settings → Functions → D1 bindings) and attach the custom domain.

## Reading the experiment

The waitlist table is the instrument. Two queries answer the gates:

```sql
-- Gate 2b: unsolicited intent at a stated price
SELECT date(created_at) AS day, count(*) AS signups, price_shown
FROM waitlist GROUP BY day ORDER BY day;

-- Which channel produced it
SELECT coalesce(referer, 'direct') AS source, count(*) AS n
FROM waitlist GROUP BY source ORDER BY n DESC;
```

`price_shown` is recorded per row on purpose. If the price changes mid-test,
earlier intent stays interpretable instead of collapsing into an undated list
of addresses.

## The scanner (Cloud Run)

The scanner is stateless and stores nothing. Deploy from the repo root:

```bash
gcloud run deploy flagrante-scan \
  --source . \
  --region europe-west1 \
  --allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --timeout 300 \
  --concurrency 20 \
  --min-instances 0 \
  --max-instances 4
```

`--min-instances 0` is what keeps this free; the cost is a cold start that
includes the KEV download, so the first scan after an idle period is slow.
`europe-west1` because the users are EU manufacturers and the SBOM should not
take a detour across the Atlantic even though it is never stored.

Then map `scan.flagrante.dev` to the service and point the landing at it. The page
picks the URL up from `window.FLAGRANTE_SCANNER` if set, otherwise defaults to
`https://scan.flagrante.dev` in production and `http://127.0.0.1:8904` in dev.

Add the production origin to `ALLOWED_ORIGINS` in `server/app.py` before
deploying, or the browser will refuse the response.

### Verified locally

| Case | Result |
|---|---|
| 5-component SBOM (log4j + jackson, pathological) | 200 in 15.3 s |
| 60-component SBOM | 200 in 2.9 s |
| Malformed JSON | 400 with a readable reason |
| Unknown format | 400 naming CycloneDX and SPDX |
| Over 5 MB | 413, body drained so the status lands |
| Over 1,000 components | 413, refuses a partial scan |
| Feed unreachable | 503, never an empty-looking result |
| CORS, allowed origin | header present |
| CORS, foreign origin | header absent, browser blocks |

## Reading the signal table

`signal` is S3 running as a by-product of S4 — who showed up and what they are
doing about Article 14, with no interviews and no email addresses.

```sql
-- What kind of company actually shows up
SELECT doing, count(*) AS n FROM signal GROUP BY doing ORDER BY n DESC;

-- Do people with a real finding behave differently?
SELECT CASE WHEN clock_running > 0 THEN 'had a live finding' ELSE 'clean scan' END AS bucket,
       count(*) AS scans, round(avg(components_checked)) AS median_components
FROM signal GROUP BY bucket;
```

## Reading the gates

These are the queries that decide the experiment. Run them, do not eyeball a
dashboard.

```sql
-- GATE 1: qualified activations per week. The bar is >500 in four weeks with
-- week-on-week growth, or any single week >200. Under 150, or flat, kills it.
SELECT strftime('%Y-W%W', first_seen) AS week, count(*) AS activations
FROM visitor WHERE scans > 0
GROUP BY week ORDER BY week;

-- GATE 2a: the number that matters most. Of people who ran a real scan, what
-- share came back later without being emailed? The bar is 10% at 30 days.
-- Under 5% means they want a one-time answer, not a subscription -- which
-- kills the EUR/month thesis while validating a cheaper one-shot product.
SELECT
  sum(CASE WHEN scans > 0 THEN 1 ELSE 0 END) AS activated,
  sum(CASE WHEN scans > 0 AND julianday(last_seen) - julianday(first_seen) >= 7
      THEN 1 ELSE 0 END) AS returned_7d,
  sum(CASE WHEN scans > 0 AND julianday(last_seen) - julianday(first_seen) >= 30
      THEN 1 ELSE 0 END) AS returned_30d
FROM visitor;

-- GATE 2b: unsolicited intent at a stated price. The bar is 15 signups.
SELECT price_bucket, price_shown, count(*) AS signups
FROM waitlist GROUP BY price_bucket, price_shown;

-- THE PRICE TEST: conversion by arm. Denominator is everyone who saw that
-- price and scanned; numerator is who then joined the list. If arm B converts
-- at more than a third of arm A's rate, the higher price is free money.
SELECT v.price_bucket,
       count(DISTINCT v.id) AS scanners,
       count(DISTINCT w.visitor_id) AS signups,
       round(100.0 * count(DISTINCT w.visitor_id) / count(DISTINCT v.id), 1) AS pct
FROM visitor v LEFT JOIN waitlist w ON w.visitor_id = v.id
WHERE v.scans > 0
GROUP BY v.price_bucket;
```

### What the return number is not

`visitor.id` is a random value in one browser's localStorage. A person who
returns on a second machine, in a private window, or after clearing site data
counts as new. **The measured return rate is therefore a floor, not an
estimate.** For a kill decision that is the right direction to be wrong in: we
would rather stop a marginal business than continue one on a flattered number.

## What is not built yet

- **Rate limiting that survives scale-out.** The in-process limiter only binds
  one instance; Cloudflare rate limiting in front of `scan.flagrante.dev` is the
  real control.
- **No email is ever sent.** The waitlist collects addresses and nothing
  delivers to them. Before the first send, that needs a real sender identity
  and an unsubscribe path.
