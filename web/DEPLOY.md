# Deploying redhand.dev

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
wrangler d1 create redhand

# 2. Apply the schema
wrangler d1 execute redhand --remote --file=schema.sql

# 3. Ship
wrangler pages deploy . --project-name=redhand
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
gcloud run deploy redhand-scan \
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

Then map `scan.redhand.dev` to the service and point the landing at it. The page
picks the URL up from `window.REDHAND_SCANNER` if set, otherwise defaults to
`https://scan.redhand.dev` in production and `http://127.0.0.1:8904` in dev.

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

## What is not built yet

- **A real CI run of `action.yml`.** It is written but has never executed on a
  GitHub runner, so treat it as unverified.
- **Rate limiting that survives scale-out.** The in-process limiter only binds
  one instance; Cloudflare rate limiting in front of `scan.redhand.dev` is the
  real control.
- **Nothing measures returning users yet.** Gate 2 needs a 30-day return rate,
  and neither table records a repeat visit. That is the next thing to build,
  and it matters more than any feature.
