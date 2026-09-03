# redhand

**Which of your components start a CRA Article 14 24-hour clock.**

Since 11 September 2026, a manufacturer placing a product with digital elements
on the EU market must send an early warning within **24 hours** of becoming
aware that a vulnerability in that product is **actively exploited**.

Every SBOM scanner on the market tells you which components are *vulnerable*.
That is not the question Article 14 asks. Thousands of CVEs are vulnerabilities;
a few hundred are being exploited. Only the second group starts a clock.

`redhand` makes that distinction the whole output.

```
24-HOUR CLOCK LIKELY RUNNING  (2)
  Confirmed exploited in the wild -- CISA KEV

  CVE-2021-44228  org.apache.logging.log4j/log4j-core@2.14.1
      listed in CISA KEV since 2021-12-10 as exploited in the wild, linked to ransomware campaigns

ASSESS TODAY  (16)
  Elevated exploitation probability, not yet confirmed
  ...

VERDICT
  1 component carries 2 vulnerabilities confirmed exploited in the wild. If any
  of these ship in a product you place on the EU market, assess Article 14
  reporting now.

ARTICLE 14 CASCADE
  Early warning     2026-09-04 17:10 UTC   (24h)
  Notification      2026-09-06 17:10 UTC   (72h)
  Final report      2026-09-17 17:10 UTC   (14d)
```

## Use it

You need an SBOM. If you do not have one, generate it free — `redhand` does not
duplicate that job, because [syft](https://github.com/anchore/syft) and
[cdxgen](https://github.com/CycloneDX/cdxgen) already do it well.

```bash
pip install redhand
syft dir:. -o cyclonedx-json | redhand
```

Or against a file, in CI, or as JSON:

```bash
redhand sbom.json
redhand sbom.json --json > result.json
redhand sbom.json --all          # include findings with no exploitation signal
redhand sbom.json --fail-on urgent
```

Exit codes: `0` nothing at the chosen level, `1` confirmed exploited,
`2` urgent (with `--fail-on urgent`), `3` the scan could not complete.

### GitHub Action

```yaml
- uses: actions/checkout@v4
- run: syft dir:. -o cyclonedx-json > sbom.json
- uses: pacordelcw/redhand@v1
  with:
    sbom: sbom.json
    fail-on: exploited
```

## How it decides

Three public feeds, no API keys:

| Feed | Answers |
|---|---|
| [OSV](https://osv.dev) | which components carry known vulnerabilities |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | which CVEs are **confirmed exploited in the wild** |
| [FIRST EPSS](https://www.first.org/epss/) | probability of exploitation within 30 days |

| Tier | Trigger |
|---|---|
| **24-hour clock likely running** | CVE listed in CISA KEV |
| **Assess today** | EPSS ≥ 10%, not in KEV |
| **Track** | known vulnerability, no exploitation signal |
| **Cannot be checked** | no package URL in the SBOM |

## What this is not

`redhand` is an **exposure indicator**. It is not a conformity assessment, not
legal advice, and not a determination that no reporting obligation exists.

Three limits worth stating plainly, because a tool in this space that hides
them is not worth trusting:

1. **It cannot tell whether vulnerable code is reachable in your product.**
   A KEV match means the CVE is exploited somewhere in the world, not that
   *your* product is being attacked. Article 14 turns on the vulnerability
   being in the product and actively exploited. That judgement is yours.

2. **"Actively exploited" is not perfectly determinable from public data.**
   KEV lags real-world exploitation, and EPSS is a model, not an observation.
   Absence of a signal here is not evidence of absence in the world.

3. **There is deliberately no "you are compliant" outcome.** Over-flagging
   costs you an afternoon; under-flagging costs up to €15 million or 2.5% of
   global turnover. Every threshold in this tool is set by that asymmetry, and
   there is a test suite that fails the build if a future change ever softens
   the wording into reassurance.

If a feed is unreachable, `redhand` refuses to print a result rather than
printing an empty one — an unreachable exploitation feed and a clean scan look
identical and mean opposite things.

## Development

No dependencies, no network in the test suite:

```bash
python -m unittest discover -s tests
```

Apache-2.0.
