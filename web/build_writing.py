"""Generate the writing pages.

One template, three articles, so the styling cannot drift between them and a
change lands everywhere at once. Run from web/:

    python build_writing.py

Writes into public/writing/. The pages are plain static HTML with the CSS
inlined -- same reasoning as the report the CLI emits: no build step, no
framework, and it will still render in ten years.
"""

from __future__ import annotations

import pathlib
import re

OUT = pathlib.Path(__file__).parent / "public" / "writing"

STYLE = """
:root{
  --ground:#FBFAF9; --panel:#FFFFFF; --sunk:#F1EFED;
  --ink:#16130F; --muted:#5E574F; --faint:#8D857B;
  --rule:#DFDAD4; --rule-firm:#C2BAB1;
  --caught:#B32D22; --caught-wash:#FBEAE7;
  --elevated:#8A5B00; --steady:#3F6B57;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --ground:#131210; --panel:#1B1917; --sunk:#221F1C;
    --ink:#F0EBE4; --muted:#A79E93; --faint:#7A7269;
    --rule:#2C2825; --rule-firm:#413B36;
    --caught:#FF7A67; --caught-wash:#2E1A16;
    --elevated:#E5A83C; --steady:#67B394;
  }
}
:root[data-theme="dark"]{
  --ground:#131210; --panel:#1B1917; --sunk:#221F1C;
  --ink:#F0EBE4; --muted:#A79E93; --faint:#7A7269;
  --rule:#2C2825; --rule-firm:#413B36;
  --caught:#FF7A67; --caught-wash:#2E1A16;
  --elevated:#E5A83C; --steady:#67B394;
}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);
  font-family:Chivo,-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  font-size:17px;line-height:1.68;-webkit-font-smoothing:antialiased}
.wrap{max-width:700px;margin:0 auto;padding:0 24px 90px}
code,.mono{font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Consolas,monospace}
code{font-size:.88em;background:var(--sunk);padding:2px 5px}
a{color:var(--caught)}
a:focus-visible{outline:2px solid var(--steady);outline-offset:2px}
header.top{display:flex;align-items:center;justify-content:space-between;padding:22px 0;
  border-bottom:1px solid var(--rule);gap:18px;flex-wrap:wrap}
.brand{font-weight:800;font-size:19px;letter-spacing:-.02em;text-decoration:none;color:var(--ink)}
.brand span{color:var(--caught)}
.top nav a{color:var(--muted);text-decoration:none;font-family:"JetBrains Mono",monospace;font-size:12px}
h1{font-size:clamp(31px,5.2vw,44px);font-weight:800;letter-spacing:-.028em;line-height:1.08;
  margin:52px 0 16px;text-wrap:balance}
.dateline{font-family:"JetBrains Mono",monospace;font-size:11.5px;color:var(--faint);
  letter-spacing:.05em;margin:0 0 34px}
.lede{font-size:20px;line-height:1.5;color:var(--muted);margin:0 0 32px}
.lede strong{color:var(--ink);font-weight:600}
h2{font-size:23px;font-weight:800;letter-spacing:-.02em;margin:44px 0 12px;line-height:1.25;text-wrap:balance}
h3{font-size:17px;font-weight:700;margin:30px 0 8px}
p{margin:0 0 17px}
strong{font-weight:600}
blockquote{margin:0 0 20px;padding:2px 0 2px 20px;border-left:3px solid var(--rule-firm);
  color:var(--muted);font-size:16.5px}
table{width:100%;border-collapse:collapse;border:1px solid var(--rule);background:var(--panel);
  margin:0 0 22px;font-size:15px}
th,td{padding:11px 13px;text-align:left;border-bottom:1px solid var(--rule)}
th{font-family:"JetBrains Mono",monospace;font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--faint);font-weight:600;background:var(--sunk)}
tr:last-child td{border-bottom:none}
td.n{font-family:"JetBrains Mono",monospace;font-variant-numeric:tabular-nums;white-space:nowrap}
.hit{color:var(--caught);font-weight:600}
ul,ol{margin:0 0 20px;padding-left:22px}
li{margin-bottom:10px}
pre{background:var(--panel);border:1px solid var(--rule);padding:16px 18px;overflow-x:auto;
  margin:0 0 22px}
pre code{background:none;padding:0;font-size:13px;line-height:1.7}
.note{background:var(--panel);border-left:3px solid var(--steady);padding:18px 20px;margin:0 0 24px;
  font-size:16px}
.note p:last-child{margin:0}
.note.warn{border-left-color:var(--caught);background:var(--caught-wash)}
.cta{border:1px solid var(--rule-firm);background:var(--sunk);padding:24px;margin:38px 0 0}
.cta p{margin:0 0 12px;font-size:16px}
.cta p:last-child{margin:0}
.cta code{background:var(--panel);border:1px solid var(--rule);padding:3px 8px}
footer.end{border-top:1px solid var(--rule);margin-top:44px;padding:24px 0 0;
  font-family:"JetBrains Mono",monospace;font-size:11px;color:var(--faint);line-height:1.8}
footer.end a{color:var(--muted)}
"""

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Flagrante</title>
<meta name="description" content="{desc}">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:type" content="article">
<link rel="canonical" href="https://flagrante.dev/writing/{slug}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Chivo:wght@400;600;800&family=JetBrains+Mono:wght@400;600&display=swap">
<style>{style}</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <a class="brand" href="/">Fla<span>grante</span></a>
  <nav><a href="/">&larr; Flagrante</a></nav>
</header>
<h1>{title}</h1>
<p class="dateline">{date}{byline}</p>
{body}
<div class="cta">
  <p><strong>Flagrante</strong> reads an SBOM and tells you which components carry a
  vulnerability CISA says is being exploited &mdash; the ones that start an Article 14
  clock, separated from the thousands that do not.</p>
  <p><code>pip install flagrante</code> &nbsp;then&nbsp; <code>syft dir:. -o cyclonedx-json | flagrante</code></p>
  <p>Or <a href="/#scan">drop an SBOM in the browser</a>. It is never stored, anywhere.</p>
</div>
<footer class="end">
  Exposure indicator only. Not a conformity assessment, not legal advice, and not a
  determination that no reporting obligation exists.<br>
  <a href="/privacy">Privacy</a> &middot; <a href="https://github.com/pacordelcw/flagrante">Source</a>
</footer>
</div>
</body>
</html>
"""


def build(slug: str, title: str, desc: str, date: str, body: str, byline: str = "") -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    html = PAGE.format(
        slug=slug, title=title, desc=desc, date=date, body=body.strip(),
        style=STYLE, byline=byline,
    )
    (OUT / f"{slug}.html").write_text(html, encoding="utf-8", newline="")
    words = len(re.sub(r"<[^>]+>", " ", body).split())
    print(f"  {slug}.html  ~{words} words")


if __name__ == "__main__":
    from articles import ARTICLES
    for a in ARTICLES:
        build(**a)
    print(f"\n  wrote {len(ARTICLES)} pages to {OUT}")
