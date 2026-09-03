-- D1 schema for the Redhand waitlist.
-- Apply with:  wrangler d1 execute redhand --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS waitlist (
  email         TEXT PRIMARY KEY,
  price_shown   INTEGER,          -- the price on screen at signup, in whole units
  currency      TEXT DEFAULT 'EUR',
  country       TEXT,             -- from CF-IPCountry: tells us the channel's reach
  referer       TEXT,             -- which page produced the intent
  created_at    TEXT NOT NULL,
  seen_again_at TEXT              -- set when an existing address submits again
);

CREATE INDEX IF NOT EXISTS waitlist_created ON waitlist (created_at);


-- Anonymous post-scan signal: S3 as a by-product of S4.
-- No email, no component names, no SBOM. Counts and two answers.
CREATE TABLE IF NOT EXISTS signal (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  makes              TEXT,      -- free text, what they build
  doing              TEXT,      -- one of a fixed option set
  components_checked INTEGER,
  sbom_format        TEXT,
  clock_running      INTEGER,
  urgent_review      INTEGER,
  monitor            INTEGER,
  unresolvable       INTEGER,
  country            TEXT,
  created_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS signal_created ON signal (created_at);
