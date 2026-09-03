"""Standalone HTML result page.

Lives inside the tool rather than the web service on purpose: the CLI, the
GitHub Action and the hosted scanner all render from this one function, so the
page a user shares can never say something different from the terminal output
they ran.

The page is fully self-contained -- inline CSS, no scripts, no external assets
beyond a font link. It can be committed to a repo as evidence, attached to a
ticket, or served statically, and it will still render in ten years.
"""

from __future__ import annotations

import html as _html
from datetime import datetime

from .classify import Assessment, Finding, Tier, early_warning_fields

BRAND = "Flagrante"
TAGLINE = "Caught in the act, not merely vulnerable"
SITE = "flagrante.dev"

_STYLE = """
:root{
  --ground:#FBFAF9; --panel:#FFFFFF; --sunk:#F1EFED;
  --ink:#16130F; --muted:#5E574F; --faint:#8D857B;
  --rule:#DFDAD4; --rule-firm:#C2BAB1;
  --caught:#B32D22; --caught-wash:#FBEAE7;
  --elevated:#8A5B00; --elevated-wash:#FAF0DC;
  --steady:#3F6B57;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --ground:#131210; --panel:#1B1917; --sunk:#221F1C;
    --ink:#F0EBE4; --muted:#A79E93; --faint:#7A7269;
    --rule:#2C2825; --rule-firm:#413B36;
    --caught:#FF7A67; --caught-wash:#2E1A16;
    --elevated:#E5A83C; --elevated-wash:#2A2113;
    --steady:#67B394;
  }
}
:root[data-theme="dark"]{
  --ground:#131210; --panel:#1B1917; --sunk:#221F1C;
  --ink:#F0EBE4; --muted:#A79E93; --faint:#7A7269;
  --rule:#2C2825; --rule-firm:#413B36;
  --caught:#FF7A67; --caught-wash:#2E1A16;
  --elevated:#E5A83C; --elevated-wash:#2A2113;
  --steady:#67B394;
}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);
  font-family:Chivo,-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:840px;margin:0 auto;padding:0 22px 80px}
code,.mono{font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Consolas,monospace}

header.top{display:flex;align-items:baseline;justify-content:space-between;
  gap:16px;padding:26px 0 20px;border-bottom:1px solid var(--rule);flex-wrap:wrap}
.brand{font-weight:800;font-size:18px;letter-spacing:-.02em;text-decoration:none;color:var(--ink)}
.brand span{color:var(--caught)}
.top .meta{font-family:"JetBrains Mono",monospace;font-size:11.5px;color:var(--faint);letter-spacing:.03em}

.subject{padding:34px 0 8px}
.subject h1{font-size:clamp(26px,4.4vw,38px);font-weight:800;letter-spacing:-.028em;
  margin:0 0 6px;line-height:1.1;text-wrap:balance}
.subject .sub{font-family:"JetBrains Mono",monospace;font-size:12px;color:var(--faint);letter-spacing:.03em}

.verdict{border:1px solid var(--rule-firm);border-top-width:4px;background:var(--panel);
  padding:22px 24px;margin:26px 0 34px}
.verdict.caught{border-top-color:var(--caught);background:var(--caught-wash)}
.verdict.elevated{border-top-color:var(--elevated);background:var(--elevated-wash)}
.verdict .lab{font-family:"JetBrains Mono",monospace;font-size:11px;letter-spacing:.14em;
  text-transform:uppercase;margin-bottom:9px;color:var(--muted)}
.verdict.caught .lab{color:var(--caught)}
.verdict.elevated .lab{color:var(--elevated)}
.verdict p{margin:0;font-size:17.5px;line-height:1.5;max-width:60ch}

.counts{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:1px;background:var(--rule);border:1px solid var(--rule);margin:0 0 40px}
.count{background:var(--panel);padding:16px 18px}
.count .n{font-size:30px;font-weight:800;letter-spacing:-.02em;line-height:1;display:block;
  margin-bottom:6px;font-variant-numeric:tabular-nums}
.count .k{font-family:"JetBrains Mono",monospace;font-size:10.5px;letter-spacing:.06em;
  text-transform:uppercase;color:var(--faint);display:block;line-height:1.4}
.count.caught .n{color:var(--caught)}
.count.elevated .n{color:var(--elevated)}

section.group{margin:0 0 38px}
.group h2{font-size:13px;font-family:"JetBrains Mono",monospace;letter-spacing:.12em;
  text-transform:uppercase;margin:0 0 4px;font-weight:600}
.group .note{font-size:13.5px;color:var(--muted);margin:0 0 16px}
.group.caught h2{color:var(--caught)}
.group.elevated h2{color:var(--elevated)}

.rows{display:flex;flex-direction:column;gap:1px;background:var(--rule);
  border:1px solid var(--rule)}
.row{background:var(--panel);padding:15px 18px;display:grid;
  grid-template-columns:170px 1fr;gap:4px 20px;align-items:baseline}
.row .cve{font-family:"JetBrains Mono",monospace;font-size:13px;font-weight:600}
.row.caught .cve{color:var(--caught)}
.row.elevated .cve{color:var(--elevated)}
.row .comp{font-family:"JetBrains Mono",monospace;font-size:13px;word-break:break-all}
.row .why{grid-column:2;font-size:13.5px;color:var(--muted);line-height:1.5}
/* Unresolvable components have no CVE to sit in the first column, so they get
   the full width instead of being squeezed into 170px. */
.row.solo{grid-template-columns:1fr}
.more{background:var(--panel);padding:12px 18px;font-family:"JetBrains Mono",monospace;
  font-size:11.5px;color:var(--faint)}

.cascade{border:1px solid var(--rule);background:var(--panel);padding:20px 22px;margin:0 0 38px}
.cascade h2{font-size:13px;font-family:"JetBrains Mono",monospace;letter-spacing:.12em;
  text-transform:uppercase;margin:0 0 4px;font-weight:600}
.cascade .note{font-size:13.5px;color:var(--muted);margin:0 0 16px;max-width:62ch}
/* Same reason as the landing's three-cell grid: three items and auto-fit
   strands the last one beside dead space. Three-up or stacked. */
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
@media (max-width:640px){.steps{grid-template-columns:1fr}}
.step{border-left:2px solid var(--rule-firm);padding-left:13px}
.step:first-child{border-left-color:var(--caught)}
.step .w{font-family:"JetBrains Mono",monospace;font-size:10.5px;letter-spacing:.08em;
  text-transform:uppercase;color:var(--faint);display:block;margin-bottom:5px}
.step .t{font-family:"JetBrains Mono",monospace;font-size:13.5px;font-weight:600;display:block}

table.fields{width:100%;border-collapse:collapse;font-family:"JetBrains Mono",monospace;font-size:12.5px}
table.fields td{padding:9px 12px;border-bottom:1px solid var(--rule);vertical-align:top}
table.fields tr:last-child td{border-bottom:none}
table.fields td:first-child{color:var(--faint);white-space:nowrap;width:1%}
.blank{color:var(--faint);font-style:italic}

.limits{border-top:1px solid var(--rule);padding-top:26px;margin-top:44px}
.limits h2{font-size:13px;font-family:"JetBrains Mono",monospace;letter-spacing:.12em;
  text-transform:uppercase;margin:0 0 14px;font-weight:600;color:var(--muted)}
.limits ol{margin:0;padding-left:20px;max-width:64ch}
.limits li{margin-bottom:11px;font-size:14.5px;color:var(--muted);line-height:1.55}
.limits li strong{color:var(--ink);font-weight:600}

.cta{margin-top:40px;border:1px solid var(--rule-firm);background:var(--sunk);padding:24px}
.cta p{margin:0 0 12px;font-size:15px;max-width:58ch}
.cta code{background:var(--panel);border:1px solid var(--rule);padding:3px 8px;font-size:13px;display:inline-block}
.cta a{color:var(--caught);font-weight:600}
footer.end{margin-top:34px;font-family:"JetBrains Mono",monospace;font-size:11px;
  color:var(--faint);line-height:1.7}
a:focus-visible{outline:2px solid var(--steady);outline-offset:2px}
@media (max-width:600px){
  .row{grid-template-columns:1fr}
  .row .why{grid-column:1}
}
"""


def _esc(value: object) -> str:
    return _html.escape(str(value), quote=True)


def _stamp(moment: datetime) -> str:
    return moment.strftime("%d %b %Y, %H:%M UTC")


def _rows(findings: list[Finding], css_class: str, limit: int | None = None) -> str:
    shown = findings[:limit] if limit else findings
    parts = []
    for finding in shown:
        parts.append(
            f'<div class="row {css_class}">'
            f'<span class="cve">{_esc(finding.primary_cve)}</span>'
            f'<span class="comp">{_esc(finding.component.label)}</span>'
            f'<span class="why">{_esc(finding.reason)}</span>'
            "</div>"
        )
    if limit and len(findings) > limit:
        parts.append(
            f'<div class="more">and {len(findings) - limit} more at this level</div>'
        )
    return "".join(parts)


def _cascade(assessment: Assessment) -> str:
    deadlines = assessment.deadlines
    steps = [
        ("within 24 hours", "Early warning", deadlines["early_warning"]),
        ("within 72 hours", "Vulnerability notification", deadlines["notification"]),
        ("within 14 days", "Final report", deadlines["final_report"]),
    ]
    cells = "".join(
        f'<div class="step"><span class="w">{_esc(window)}</span>'
        f'<span class="t">{_esc(name)}</span>'
        f'<span class="w" style="margin-top:5px">{_esc(_stamp(when))}</span></div>'
        for window, name, when in steps
    )
    return (
        '<div class="cascade"><h2>Article 14 cascade</h2>'
        "<p class=\"note\">Counted from the moment you became aware, which may well "
        "predate this scan. Submitted to the ENISA Single Reporting Platform and the "
        "CSIRT of your member state of main establishment.</p>"
        f'<div class="steps">{cells}</div></div>'
    )


def _early_warning(assessment: Assessment) -> str:
    if not assessment.clock_running:
        return ""
    fields = early_warning_fields(assessment.clock_running[0], assessment)
    rows = []
    for key, value in fields.items():
        label = _esc(key.replace("_", " "))
        blank = value.startswith("<")
        cell = (
            f'<span class="blank">{_esc(value)}</span>' if blank else _esc(value)
        )
        rows.append(f"<tr><td>{label}</td><td>{cell}</td></tr>")
    return (
        '<div class="cascade"><h2>What the early warning must carry</h2>'
        '<p class="note">The italic fields are the ones only you can fill. They are '
        "left blank rather than guessed.</p>"
        f'<table class="fields"><tbody>{"".join(rows)}</tbody></table></div>'
    )


def render_html(assessment: Assessment, scan_url: str | None = None) -> str:
    """Produce a complete, standalone HTML document for one scan."""
    running = assessment.clock_running
    urgent = assessment.urgent
    monitor = assessment.monitor
    unresolvable = assessment.unresolvable

    if running:
        tone, lab = "caught", "Caught in the act"
    elif urgent:
        tone, lab = "elevated", "Not yet confirmed"
    else:
        tone, lab = "", "Point-in-time observation"

    subject = assessment.document.subject or "Unnamed SBOM"
    doc = assessment.document

    blocks: list[str] = []

    blocks.append(
        f'<div class="verdict {tone}"><div class="lab">{_esc(lab)}</div>'
        f"<p>{_esc(assessment.verdict)}</p></div>"
    )

    blocks.append(
        '<div class="counts">'
        f'<div class="count caught"><span class="n">{len(running)}</span>'
        '<span class="k">Confirmed exploited</span></div>'
        f'<div class="count elevated"><span class="n">{len(urgent)}</span>'
        '<span class="k">Elevated probability</span></div>'
        f'<div class="count"><span class="n">{len(monitor)}</span>'
        '<span class="k">No exploit signal</span></div>'
        f'<div class="count"><span class="n">{len(unresolvable)}</span>'
        '<span class="k">Could not be checked</span></div>'
        "</div>"
    )

    if running:
        blocks.append(
            '<section class="group caught"><h2>24-hour clock likely running</h2>'
            '<p class="note">Listed in the CISA Known Exploited Vulnerabilities '
            "catalogue &mdash; observed being exploited in the wild.</p>"
            f'<div class="rows">{_rows(running, "caught")}</div></section>'
        )

    if urgent:
        blocks.append(
            '<section class="group elevated"><h2>Assess today</h2>'
            '<p class="note">EPSS puts these above a 10% chance of exploitation '
            "within 30 days. Not confirmed, but this is the group obligations "
            "tend to come from next.</p>"
            f'<div class="rows">{_rows(urgent, "elevated", limit=12)}</div></section>'
        )

    if running or urgent:
        blocks.append(_cascade(assessment))
        blocks.append(_early_warning(assessment))

    if unresolvable:
        names = "".join(
            f'<div class="row solo"><span class="comp">{_esc(c.label)}</span></div>'
            for c in unresolvable[:12]
        )
        extra = (
            f'<div class="more">and {len(unresolvable) - 12} more</div>'
            if len(unresolvable) > 12
            else ""
        )
        blocks.append(
            '<section class="group"><h2>Could not be checked</h2>'
            '<p class="note">These components carry no package URL, so no feed can '
            "be queried for them. That is an unknown, not a clear.</p>"
            f'<div class="rows">{names}{extra}</div></section>'
        )

    blocks.append(
        '<div class="limits"><h2>What this is not</h2><ol>'
        "<li><strong>Not a determination that your product is affected.</strong> "
        "A KEV listing means the vulnerability is exploited somewhere in the world, "
        "not that your build is reachable or under attack. Article 14 turns on the "
        "vulnerability being in the product and actively exploited. That judgement "
        "is yours.</li>"
        "<li><strong>Not complete.</strong> KEV lags real exploitation and EPSS is a "
        "model, not an observation. Absence of a signal here is not evidence of "
        "absence in the world.</li>"
        "<li><strong>Not a conformity assessment, and not legal advice.</strong> "
        "There is deliberately no outcome on this page that means you are in the "
        "clear.</li>"
        "</ol></div>"
    )

    cta_link = (
        f'<a href="https://{SITE}">{SITE}</a>' if not scan_url else f'<a href="{_esc(scan_url)}">{_esc(scan_url)}</a>'
    )
    blocks.append(
        '<div class="cta">'
        "<p>This is a snapshot. Exploitation status changes daily, and the 24-hour "
        "window starts from awareness &mdash; not from your next scan.</p>"
        f"<p><code>pip install flagrante</code> &nbsp; then &nbsp; "
        f"<code>syft dir:. -o cyclonedx-json | flagrante</code></p>"
        f"<p>Continuous watching and a dated evidence trail: {cta_link}</p>"
        "</div>"
    )

    meta = (
        f"{_esc(doc.format)} {_esc(doc.spec_version or '')} &middot; "
        f"{assessment.components_checked} components checked &middot; "
        f"{_esc(_stamp(assessment.scanned_at))}"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(subject)} &mdash; {BRAND}</title>
<meta name="description" content="{_esc(assessment.verdict[:180])}">
<meta name="robots" content="noindex">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Chivo:wght@400;600;800&family=JetBrains+Mono:wght@400;600&display=swap">
<style>{_STYLE}</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <a class="brand" href="https://{SITE}">Red<span>hand</span></a>
  <span class="meta">{TAGLINE}</span>
</header>
<div class="subject">
  <h1>{_esc(subject)}</h1>
  <div class="sub">{meta}</div>
</div>
{"".join(blocks)}
<footer class="end">
  Generated by {BRAND} from CISA KEV, FIRST EPSS and OSV.<br>
  Exposure indicator only. Not a conformity assessment, not legal advice, and not
  a determination that no reporting obligation exists.
</footer>
</div>
</body>
</html>
"""
