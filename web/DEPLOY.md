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
| Scanner | Cloudflare Containers | $5/month (Workers Paid), billed per 10ms of runtime |

The scanner is the only paid line, and it was chosen over Google Cloud Run --
which would have been free -- deliberately. Cloud Run meant a second cloud
account, a second card on file, and a second place to remember to switch off.
At this size the operational surface costs more than the sixty dollars a year.
Total running cost is therefore ~$72/year, not the ~$12 the heading above
originally promised.

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

## The scanner (Cloudflare Containers)

The scanner is a Worker fronting a container, configured in the repo-root
`wrangler.toml`. It is stateless and stores nothing. Deploy from the repo root,
**not** from `web/`:

```bash
export CLOUDFLARE_API_TOKEN=...   # needs Workers Scripts: Edit and Containers: Edit
export CLOUDFLARE_ACCOUNT_ID=...
npx wrangler deploy
```

Docker must be running: Wrangler builds the image locally and pushes it to
Cloudflare's registry.

Two things the documentation does not say, both found by hitting them:

- **Wrangler uses the Dockerfile's own directory as the build context**, not the
  config's. That is why the Dockerfile sits at the repo root — under `server/`,
  `COPY flagrante/` has nothing to copy.
- That build context is the repo root, which holds `node_modules`, so the root
  `.dockerignore` is load-bearing. Without it every build uploads ~190 MB.

`max_instances = 1` is a cost ceiling as much as a capacity setting, since
containers bill per 10ms of runtime. `sleepAfter = "10m"` in `worker/index.js`
trades idle cost against cold starts, which include the CISA KEV download.
Measured cold start is about 6 seconds, warm scans about 3.

The custom domain is attached through the API rather than as a route in the
config, which is why setting `workers_dev = false` does not remove it:

```
PUT /client/v4/accounts/{account}/workers/domains
{"zone_id": "...", "hostname": "scan.flagrante.dev",
 "service": "flagrante-scan", "environment": "production"}
```

The landing picks the scanner URL up from `window.FLAGRANTE_SCANNER` if set,
otherwise defaults to `https://scan.flagrante.dev` in production and
`http://127.0.0.1:8904` in dev. Add any new production origin to
`ALLOWED_ORIGINS` in `server/app.py` before deploying, or the browser will
refuse the response.

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

### The thresholds were recalibrated on 3 September 2026, before any data

Recorded here because the timing is the whole point. **No result had been
observed when this changed** — the visitor table was at zero and the site had
been live for hours. Lowering a threshold after missing it is rationalisation;
lowering it because the question changed, before the first data point, is not.
Anyone reading this later can check the commit date against the first non-empty
row.

**What changed.** The original bars were derived from a $20M ARR target: roughly
1,100 customers at $1,500/month, which at a 2-4% activation-to-paid rate needs
tens of thousands of qualified activations. Hence "500 in four weeks".

That target turned out to be the *test*, not the goal. The real question is
whether an agent can run a business at all, and the smallest result that answers
it conclusively is **one paying customer, acquired with no human selling, and
retained for three months**. One stranger who found it alone, decided it was
worth money, and kept paying. Everything past that is scale, which is a
different and much easier question.

This makes the experiment repeatable, which matters more than the lower bar. At
$20M you get one attempt every three years. At one paying customer you get one
per quarter — the difference between a bet and an experiment.

| Gate | Was | Now | Why |
|---|---|---|---|
| 1 — activations | >500 in 4 weeks | **~50 in 4 weeks** | One customer at 2-4% conversion needs 25-50, not tens of thousands |
| 2 — return rate | ≥10% at 30 days | **unchanged** | Measures product-market fit, not scale. Still the one that decides. |
| 3 — revenue | *did not exist* | **one paying customer by week 12** | The actual test. Nothing before it proves anything. |

Gate 1 moving lifts its odds from roughly 25-30% to around 65%. Gate 2 does not
move and stays near 35%. Overall odds of Flagrante proving the thesis: **~11%**,
resolved in twelve weeks rather than three years.

**Consequence for the build:** there is currently no way to take money. Under the
old target that was fine, because charging came in week 6+. Under this one,
charging *is* the test, so it moves onto the critical path — but only after gate
2. If nobody returns there is nobody to charge, and the company formation that
taking money requires would have been wasted.

```sql
-- GATE 1: qualified activations per week. The bar is ~50 over four weeks.
-- Under 15, or flat week on week, kills it: that is not a channel, that is
-- noise.
SELECT strftime('%Y-W%W', first_seen) AS week, count(*) AS activations
FROM visitor WHERE scans > 0
GROUP BY week ORDER BY week;

-- GATE 2a: the number that matters most, and the one that did not move.
-- Of people who ran a real scan, what share came back later without being
-- emailed? The bar is 10% at 30 days. Under 5% means they want a one-time
-- answer, not a subscription -- which kills the per-month thesis while
-- validating a cheaper one-shot product. That is a finding, not a failure.
SELECT
  sum(CASE WHEN scans > 0 THEN 1 ELSE 0 END) AS activated,
  sum(CASE WHEN scans > 0 AND julianday(last_seen) - julianday(first_seen) >= 7
      THEN 1 ELSE 0 END) AS returned_7d,
  sum(CASE WHEN scans > 0 AND julianday(last_seen) - julianday(first_seen) >= 30
      THEN 1 ELSE 0 END) AS returned_30d
FROM visitor;

-- GATE 2b: unsolicited intent at a stated price. The bar drops to 5 signups
-- for the same reason gate 1 did -- we need one buyer, not a pipeline.
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

### Bots are already in the visitor table

Within seconds of the certificate being issued, crawlers that watch Certificate
Transparency logs began loading the page and firing the visit ping — eleven of
them before a single human had the URL. They will keep arriving.

Both gates are insulated from this by construction, because both filter on
`scans > 0` and a crawler does not upload an SBOM. `visitor.visits` is
therefore inflated and should not be read as human traffic; only rows with
`scans > 0` mean anything. Do not "fix" this by counting page views.

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
