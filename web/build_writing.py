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
.consent{position:fixed;left:0;right:0;bottom:0;z-index:50;background:var(--panel);
  border-top:2px solid var(--ink);padding:18px 24px;display:none}
.consent.show{display:block}
.consent-in{max-width:760px;margin:0 auto;display:flex;gap:18px;align-items:center;
  justify-content:space-between;flex-wrap:wrap}
.consent p{margin:0;font-size:14px;color:var(--muted);max-width:58ch;line-height:1.55}
.consent p strong{color:var(--ink);font-weight:600}
.consent .acts{display:flex;gap:9px;flex-shrink:0}
.consent button{padding:9px 18px;font-family:Chivo,sans-serif;font-size:14.5px;font-weight:600;
  cursor:pointer;border:1px solid var(--rule-firm);background:var(--ground);color:var(--ink)}
.consent button.yes{background:var(--caught);border-color:var(--caught);color:#fff}
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
<div class="consent" id="consent" role="dialog" aria-live="polite" aria-label="Measurement consent">
  <div class="consent-in">
    <p>
      May we keep <strong>one random number in your browser</strong> so we can tell a
      returning reader from a new one, and see which writing brings people here?
      No cookies, no account, no email, no IP address, nothing that identifies you
      &mdash; and the page reads the same either way. <a href="/privacy">What we collect</a>.
    </p>
    <div class="acts">
      <button type="button" id="consent-no">No thanks</button>
      <button type="button" class="yes" id="consent-yes">Allow</button>
    </div>
  </div>
</div>

<script>
/* Measurement for the writing. Identical consent rules to the landing: no
   identifier is generated, stored or sent until someone agrees, declining
   erases anything already there, and the article reads the same either way.
   The referring host is what this exists to capture -- an arrival from a search
   engine is the only evidence that the content channel works at all. */
(function () {
  var ID = 'flagrante.vid', CONSENT = 'flagrante.consent';
  function put(k,v){ try{ localStorage.setItem(k,v); }catch(e){} }
  function get(k){ try{ return localStorage.getItem(k); }catch(e){ return null; } }
  function newId(){
    try { var b=new Uint8Array(12); crypto.getRandomValues(b);
      return Array.prototype.map.call(b,function(x){return ('0'+x.toString(16)).slice(-2);}).join('');
    } catch(e){ return (Date.now().toString(36)+Math.random().toString(36).slice(2,14))
      .replace(/[^a-z0-9]/g,'').slice(0,24); }
  }
  var consent = get(CONSENT), id = consent === 'yes' ? get(ID) : null;

  function ping(){
    if (consent !== 'yes') return;
    if (!id) { id = newId(); put(ID, id); }
    try {
      fetch('/api/visit', { method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ id:id, event:'visit' }), keepalive:true }).catch(function(){});
    } catch(e){}
  }
  function forget(prev){
    try { localStorage.removeItem(ID); localStorage.removeItem('flagrante.bucket'); } catch(e){}
    if (!prev) return;
    try { fetch('/api/forget', { method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ id:prev }), keepalive:true }).catch(function(){}); } catch(e){}
  }
  function decide(a){
    var prev = id || get(ID);
    consent = a; put(CONSENT, a);
    var box = document.getElementById('consent');
    if (box) box.classList.remove('show');
    if (a === 'yes') ping(); else { id = null; forget(prev); }
  }
  function wire(){
    var box = document.getElementById('consent');
    if (!box) return;
    document.getElementById('consent-yes').addEventListener('click',function(){decide('yes');});
    document.getElementById('consent-no').addEventListener('click',function(){decide('no');});
    if (consent !== 'yes' && consent !== 'no') box.classList.add('show');
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
  ping();
})();
</script>

</body>
</html>
"""


def build(slug: str, title: str, desc: str, date: str, body: str, byline: str = "") -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    # Plain substitution rather than str.format: the template now carries
    # JavaScript, and every brace in it would otherwise be read as a field.
    html = PAGE
    for key, value in (
        ("{slug}", slug), ("{title}", title), ("{desc}", desc),
        ("{date}", date), ("{byline}", byline), ("{style}", STYLE),
        ("{body}", body.strip()),
    ):
        html = html.replace(key, value)
    (OUT / f"{slug}.html").write_text(html, encoding="utf-8", newline="")
    words = len(re.sub(r"<[^>]+>", " ", body).split())
    print(f"  {slug}.html  ~{words} words")


if __name__ == "__main__":
    from articles import ARTICLES
    for a in ARTICLES:
        build(**a)
    print(f"\n  wrote {len(ARTICLES)} pages to {OUT}")
