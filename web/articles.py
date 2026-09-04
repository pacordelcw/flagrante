"""Article content. Prose lives here, layout lives in build_writing.py.

Numbers in these pieces come from the CISA KEV catalogue released 2 September
2026 (1,694 entries), analysed with the script in this repo. They are
reproducible: the feed is public and the classification rule is stated in the
first article rather than hidden.
"""

ARTICLES = [
    dict(
        slug="kev-is-becoming-a-dependency-problem",
        title="Half of what CISA now flags as exploited arrives through your dependency tree",
        desc="In 2022, 24% of new CISA KEV entries were libraries rather than appliances. In 2026 it is 46%. That changes who has to care about the CRA's 24-hour clock.",
        date="3 September 2026",
        body="""
<p class="lede">The Known Exploited Vulnerabilities catalogue used to be a list of
other people's problems: firewalls, VPN concentrators, mail gateways. If you did
not sell a box, it was not about you. <strong>That stopped being true, and the
shift is measurable.</strong></p>

<p>We pulled the KEV catalogue published on 2 September 2026 — 1,694 entries —
and split each one by how the software reaches a victim. Some of it is bought and
installed: a Fortinet appliance, a SonicWall gateway, a Windows component. The
rest arrives silently, as a transitive dependency, in a build nobody reviewed line
by line.</p>

<table>
  <thead><tr><th>Year added</th><th>Total</th><th>Bought &amp; installed</th><th>Arrived as a dependency</th><th>Share</th></tr></thead>
  <tbody>
    <tr><td class="n">2021</td><td class="n">311</td><td class="n">218</td><td class="n">93</td><td class="n">30%</td></tr>
    <tr><td class="n">2022</td><td class="n">555</td><td class="n">420</td><td class="n">135</td><td class="n">24%</td></tr>
    <tr><td class="n">2023</td><td class="n">187</td><td class="n">118</td><td class="n">69</td><td class="n">37%</td></tr>
    <tr><td class="n">2024</td><td class="n">186</td><td class="n">121</td><td class="n">65</td><td class="n">35%</td></tr>
    <tr><td class="n">2025</td><td class="n">245</td><td class="n">139</td><td class="n">106</td><td class="n">43%</td></tr>
    <tr><td class="n">2026</td><td class="n">210</td><td class="n">113</td><td class="n hit">97</td><td class="n hit">46%</td></tr>
  </tbody>
</table>

<p><strong>The share has roughly doubled since 2022.</strong> The classification is
a heuristic — vendor and product names matched against a list of appliance and
platform vendors — so treat the exact percentages as approximate and the direction
as solid. The feed is public; the split is reproducible in an afternoon.</p>

<h2>What the recent entries look like</h2>

<p>The four most recent library entries at the time of writing, all added on
2 September 2026:</p>

<table>
  <thead><tr><th>Added</th><th>Project</th><th>CVE</th></tr></thead>
  <tbody>
    <tr><td class="n">2026-09-02</td><td>Starlette</td><td class="n">CVE-2026-48710</td></tr>
    <tr><td class="n">2026-09-02</td><td>LiteLLM</td><td class="n">CVE-2026-59822</td></tr>
    <tr><td class="n">2026-09-02</td><td>Kestra OSS</td><td class="n">CVE-2026-49869</td></tr>
    <tr><td class="n">2026-09-02</td><td>JFrog Artifactory</td><td class="n">CVE-2026-82329</td></tr>
  </tbody>
</table>

<p>Starlette is the one to look at. It is not a product anybody buys — it is what
FastAPI is built on, which means it sits inside a very large number of Python
services whose authors have never typed its name. Nobody decided to run Starlette.
They decided to run FastAPI, and Starlette came along.</p>

<p>That is the whole shift in one line. The exploited thing is no longer something
you chose. It is something you inherited.</p>

<h2>Why this lands on the Cyber Resilience Act</h2>

<p>Since 11 September 2026, a manufacturer placing a product with digital elements
on the EU market has <strong>24 hours</strong> from becoming aware that a
vulnerability in that product is <em>actively exploited</em> to send an early
warning to ENISA and their national CSIRT. Not 24 hours to fix it. 24 hours to
report it.</p>

<p>Read those two facts together and the consequence is uncomfortable. The
obligation is triggered by exploitation, exploitation is increasingly found in
ordinary libraries, and ordinary libraries are in everyone's build. <strong>The
population of companies that can have a clock start inside their product is
expanding, and most of them have not noticed because they do not think of
themselves as security vendors.</strong></p>

<div class="note warn">
<p>A company that ships a web service, uses FastAPI, and has never sold an
appliance in its life can now be four dependency hops from a CVE that CISA says is
being exploited in the wild. In 2022 that was unlikely. In 2026 it is roughly a
coin flip on any given KEV update.</p>
</div>

<h2>The number that actually matters is not 1,694</h2>

<p>There are millions of known CVEs. There are 1,694 entries in KEV. And of the
2026 additions, 21% are linked to known ransomware campaigns.</p>

<p>That ratio is the entire point of Article 14, and it is what most vulnerability
tooling blurs. A scanner that reports "312 components, 47 vulnerabilities" has told
you almost nothing about your reporting obligation, because the regulation does not
turn on whether a vulnerability exists. It turns on whether someone is using it.</p>

<blockquote>A published proof of concept, a researcher demonstrating exploitability,
or a disclosed-but-unexploited CVE does not, on its own, start the clock. Evidence
of exploitation does.</blockquote>

<p>Which means the useful question is not "how many vulnerabilities do I have"
but "how many of mine are on the list of things being exploited right now" — a
much smaller number, and a much more actionable one.</p>

<h2>What to do with this</h2>

<ol>
  <li><strong>Know what is in your build.</strong> Not the direct dependencies —
  the transitive ones, where Starlette lives. You need an SBOM, and
  <a href="https://github.com/anchore/syft">syft</a> or
  <a href="https://github.com/CycloneDX/cdxgen">cdxgen</a> will produce one free.</li>
  <li><strong>Check it against exploitation, not against severity.</strong> CVSS
  tells you how bad a vulnerability would be. KEV tells you whether it is happening.
  Only the second one is what Article 14 asks about.</li>
  <li><strong>Do it continuously, not once.</strong> KEV gained 87 entries between
  June and September 2026. A scan from last quarter says nothing about today, and
  the 24 hours run from awareness — which the regulator may reasonably date from
  when you could have known.</li>
</ol>

<p>None of that tells you whether the vulnerable code path is reachable in your
product. That judgement stays with the people who wrote it, and no tool should
pretend otherwise. But knowing which four of your three hundred components are on
the exploited list is the difference between a decision and a search.</p>
""",
    ),

    dict(
        slug="class-i-pincer",
        title="Important Class I products are caught between a standard that is not citable and a notified body that does not exist",
        desc="CRA self-assessment for Annex III Class I depends on harmonised standards. Those slipped to late 2026, and as of mid-2026 no notified bodies had been designated. Both routes are currently blocked.",
        date="3 September 2026",
        body="""
<p class="lede">If your product lands in Annex III Class I of the Cyber Resilience
Act, you have two routes to conformity. <strong>Right now, in September 2026, both
of them are obstructed</strong> — and the reason is not in any single document, it
is in the gap between two of them.</p>

<h2>The two routes</h2>

<p>The CRA sorts products with digital elements into three tiers, and the tier
determines the route:</p>

<table>
  <thead><tr><th>Tier</th><th>Route</th></tr></thead>
  <tbody>
    <tr><td><strong>Default</strong> — everything not listed in Annex III or IV</td>
        <td>Self-assessment under Module A, internal control. Permitted regardless of which technical specification you use. Roughly 90% of products.</td></tr>
    <tr><td><strong>Important, Class I</strong> — password managers, VPNs, routers, browsers, operating systems, SIEM, identity management, smart locks and cameras</td>
        <td>Self-assessment <em>only if</em> you fully apply harmonised standards, common specifications, or a European cybersecurity certification scheme. Otherwise a notified body.</td></tr>
    <tr><td><strong>Important Class II and Critical</strong> — firewalls, hypervisors, TPMs, smart meter gateways, secure elements</td>
        <td>Notified body. No self-assessment route exists.</td></tr>
  </tbody>
</table>

<p>Default-tier manufacturers are fine and can act today. Class II and Critical
know they need a third party. <strong>Class I is the awkward middle</strong>, and
its route depends on something that has not arrived.</p>

<h2>Route one: the standards are not citable yet</h2>

<p>Standardisation request M/606 was accepted by CEN, CENELEC and ETSI in April
2025, covering 41 harmonised standards, originally due Q3 2026. In early July 2026
the Commission proposed pushing those deadlines back: the A and B vulnerability
management standards to <strong>31 October 2026</strong>, the C standards to
<strong>31 December 2026</strong>.</p>

<p>Delivery is not the finish line, and this is the part that is easy to miss.
A harmonised standard only confers the Article 27 presumption of conformity
<strong>once its reference is cited in the Official Journal</strong>, which happens
after delivery, assessment, and a formal citation decision. That lag is measured in
months.</p>

<div class="note">
<p>So "the standards land in late 2026" and "you can rely on the standards in late
2026" are different statements, and only the first one is true.</p>
</div>

<h2>Route two: there were no notified bodies</h2>

<p>The CRA's rules on notified bodies started to apply on 11 June 2026. As of late
June 2026, <strong>zero notified bodies had been designated in the Commission's
NANDO database</strong>. Not few. None.</p>

<p>Article 35(2) sets 11 December 2026 as the point by which Member States should
strive to ensure sufficient notified body capacity, expressly to avoid bottlenecks
that hinder market entry. "Strive to ensure" is a best-efforts objective, not a
guarantee, and it says nothing about whether capacity will exist for any particular
product category.</p>

<p>Anyone waiting for designations to appear will be competing for scarce capacity
against everyone else who waited, in the run-up to full application on 11 December
2027.</p>

<h2>What this means in practice</h2>

<p>For a Class I manufacturer today, the honest position is that neither route can
be completed right now. That is not a reason to do nothing; it is a reason to do the
part that does not depend on either.</p>

<ul>
  <li><strong>Check your classification first, and check it against core
  functionality.</strong> The Commission's March 2026 draft guidance is explicit
  that classification turns on what the product is mainly for, not on every feature
  it contains. Products land in Class I more often by assumption than by analysis —
  a feature that would be Class I if sold standalone does not necessarily pull the
  whole product in.</li>
  <li><strong>If you are actually Default tier, say so in writing, now.</strong>
  Module A is open, unblocked, and does not wait for anyone. The blocker only exists
  for people who are genuinely in Class I.</li>
  <li><strong>Build the technical documentation either way.</strong> Annex VII —
  architecture, risk assessment, SBOM in a machine-readable format covering at
  minimum top-level dependencies, vulnerability handling evidence, a coordinated
  disclosure policy, test reports — is required on every route. Retained for ten
  years or the full support period, whichever is longer. None of that is waiting on
  a standard.</li>
</ul>

<h2>And the obligation that does not wait at all</h2>

<p>All of the above concerns the December 2027 deadline. <strong>Article 14
reporting started on 11 September 2026</strong>, applies regardless of tier, and
applies to products already on the market. Reporting is not conformity assessment:
no standard, no notified body, and no classification question stands between a
manufacturer and a 24-hour early warning obligation.</p>

<p>Which produces the strange situation many Class I manufacturers are in this
month: blocked on the thing due next year, and already live on the thing due now.</p>
""",
    ),

    dict(
        slug="the-first-24-hours",
        title="A CVE in your product just hit CISA KEV. Here is what the next 24 hours actually look like",
        desc="Article 14 gives you 24 hours from awareness. Most guides explain the rule. This one is the runbook: what starts the clock, who decides, what the early warning must contain, and what to do when you are not sure.",
        date="3 September 2026",
        body="""
<p class="lede">There is no shortage of writing explaining that the Cyber
Resilience Act requires an early warning within 24 hours. There is very little on
what those 24 hours contain. <strong>This is the second thing.</strong></p>

<div class="note warn">
<p>Nothing here is legal advice, and none of it substitutes for your own counsel or
your own assessment. It is an operational sketch of a procedure that, on
11 September 2026, became something you may have to execute at short notice.</p>
</div>

<h2>Hour 0: what actually starts it</h2>

<p>The clock starts when you become <em>aware</em> that a vulnerability
<em>contained in your product</em> is <em>actively exploited</em>. Three conditions,
and all three matter:</p>

<ul>
  <li><strong>Actively exploited</strong> is not the same as severe, or public, or
  proof-of-concept. It requires reliable evidence that a malicious actor has
  exploited it in the wild. A CVSS 9.8 with no exploitation does not start a clock.</li>
  <li><strong>Contained in your product</strong> is your judgement, not the feed's.
  A KEV listing tells you the vulnerability is exploited somewhere in the world. It
  does not tell you the vulnerable code path is reachable in your build, or that the
  affected version is the one you ship.</li>
  <li><strong>Awareness</strong> is the part people underestimate. It is not "when
  we ran the scan". If a component of yours entered KEV three weeks ago and you had
  no process that would have noticed, the defensible position is not that your clock
  started today.</li>
</ul>

<p>Which is why "we scan quarterly" is a worse answer than it sounds. The interval
between exploitation becoming public and you noticing is the part of the timeline
you control, and it is the part a regulator can most easily inspect.</p>

<h2>Hours 0–2: decide, and write down why</h2>

<p>The single most useful artefact from this phase is not the report. It is the
record of the decision.</p>

<ol>
  <li><strong>Confirm the version.</strong> KEV entries name a product, not your
  build. Does the affected version range include what you actually ship, in the
  releases still under support?</li>
  <li><strong>Confirm reachability, or accept that you cannot.</strong> Is the
  vulnerable path present and callable in your product as configured? If you cannot
  determine this within the window, the conservative reading is to report — the
  regulation does not offer "we were still investigating" as a reason for silence.</li>
  <li><strong>Write the reasoning down with a timestamp, whichever way you go.</strong>
  A decision not to report, recorded with its basis at the time, is a defensible
  position. The same decision, unrecorded, is indistinguishable from not having
  noticed.</li>
</ol>

<h2>Hours 2–24: the early warning</h2>

<p>The early warning goes to the CSIRT designated as coordinator for the Member
State of your main establishment, and to ENISA, through the Single Reporting
Platform. It is deliberately short — it is a warning, not a full analysis.</p>

<table>
  <thead><tr><th>Field</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td>The vulnerability</td><td>CVE identifier, and what the product is</td></tr>
    <tr><td>Whether it is actively exploited</td><td>This is the trigger; say what your evidence is</td></tr>
    <tr><td>Member States affected</td><td>Where the product is made available, to the best of your knowledge</td></tr>
    <tr><td>Corrective measures</td><td>What you have done or plan to do, even if the answer is "assessment in progress"</td></tr>
    <tr><td>Manufacturer and contact</td><td>Legal manufacturer, and a human who can be reached</td></tr>
  </tbody>
</table>

<p>An early warning that says "we are aware, we are assessing, here is who to call"
is a valid early warning. Waiting until you have a complete picture is how the
24 hours get missed.</p>

<h2>What comes after</h2>

<table>
  <thead><tr><th>When</th><th>What</th></tr></thead>
  <tbody>
    <tr><td class="n">24 hours</td><td>Early warning</td></tr>
    <tr><td class="n">72 hours</td><td>Vulnerability notification — fuller detail, severity, impact, any mitigations available</td></tr>
    <tr><td class="n">14 days</td><td>Final report, once a corrective measure exists</td></tr>
  </tbody>
</table>

<p>All three run from awareness, not from each other, and not from when you finished
investigating.</p>

<h2>The part you can prepare in advance</h2>

<p>Almost none of the above is doable at speed unless three things already exist
before the day you need them:</p>

<ul>
  <li><strong>An SBOM per release, retrievable.</strong> If answering "do we ship
  this component" takes a day, the 24 hours are gone before the question is settled.
  Generate it in CI and attach it to the release; syft and cdxgen do this free.</li>
  <li><strong>A named owner and an out-of-hours path.</strong> Exploitation does not
  arrive on Tuesday morning. Someone has to be able to make the call, and the
  regulator's clock does not pause for a weekend.</li>
  <li><strong>Continuous checking against exploitation, not severity.</strong> The
  triggering event happens on someone else's schedule: a CVE you already knew about
  becomes reportable the moment it starts being exploited, with no change on your
  side at all. That is the case a quarterly scan cannot catch by construction.</li>
</ul>

<p>The last one is worth restating, because it is the one that surprises people.
Nothing has to change in your code for a reporting obligation to appear. A component
you shipped two years ago, unchanged, becomes reportable because an attacker
somewhere started using a weakness in it. Your build did not move. The world did.</p>
""",
    ),
]
